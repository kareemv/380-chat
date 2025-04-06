#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include "util.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

// encryption constants
#define KEY_SIZE 32
#define IV_SIZE 16
#define MAC_SIZE 32

// shared key derived from DH
static unsigned char shared_key[KEY_SIZE * 2];
static EVP_CIPHER_CTX *enc_ctx; 
static EVP_CIPHER_CTX *dec_ctx;
static unsigned char iv[IV_SIZE];

// function prototypes for crypto
static int init_crypto();
static void cleanup_crypto();

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */

/* dhKey variables */
static dhKey server_dh_key; // server ephemeral dhKey
static dhKey client_dh_key; // client ephemeral dhKey

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);

	/* generate dhKey */
	initKey(&server_dh_key);
	if (dhGenk(&server_dh_key) != 0) {
		fprintf(stderr, "Server: Failed to generate server DH key\n");
		close(listensock);
		shredKey(&server_dh_key);
		error("dhKey generation failed");
	}
	fprintf(stderr, "Server: DH key generated successfully\n");
	
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "Server: connection made, starting session...\n");
	
	/* send server pk */
	fprintf(stderr, "Server: Sending public key...\n");
	if (sendPublicKey(sockfd, server_dh_key.PK) != 0) {
    return -1;
  }
	fprintf(stderr, "Server: Public key sent successfully\n");
	
	/* receive client pk */
	mpz_t client_pk;
	mpz_init(client_pk);
	fprintf(stderr, "Server: Waiting for client public key...\n");
	if (receivePublicKey(sockfd, client_pk) != 0) {
    mpz_clear(client_pk);
    return -1;
  }
	fprintf(stderr, "Server: Client public key received successfully\n");

	// derive shared secret 
	fprintf(stderr, "Server: Deriving shared secret...\n");
	unsigned char shared_secret[KEY_SIZE * 2];
	if (dhFinal(server_dh_key.SK, server_dh_key.PK, client_pk, shared_secret, sizeof(shared_secret)) != 0) {
		fprintf(stderr, "Server: Failed to derive shared secret\n");
		mpz_clear(client_pk);
		return -1;
	}
	fprintf(stderr, "Server: Shared secret derived successfully\n");
	
	// store shared secret and clear unused field
	memcpy(shared_key, shared_secret, sizeof(shared_secret));
	memset(shared_secret, 0, sizeof(shared_secret));

	mpz_clear(client_pk);
	
	// init crypto
	fprintf(stderr, "Server: Initializing encryption...\n");
	if (init_crypto() != 0) {
		fprintf(stderr, "Server: Failed to initialize crypto\n");
		return -1;
	}
	fprintf(stderr, "Server: Secure channel established\n");
	
	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");

	/* generate dhKey */
	initKey(&client_dh_key);
	if (dhGenk(&client_dh_key) != 0) {
		fprintf(stderr, "Client: Failed to generate client DH key\n");
		shredKey(&client_dh_key);  
		error("dhKey generation failed");
	}
	fprintf(stderr, "Client: DH key generated successfully\n");
	
	/* receive server pk  */
	mpz_t server_pk;
	mpz_init(server_pk);
	fprintf(stderr, "Client: Waiting for server public key...\n");
	if (receivePublicKey(sockfd, server_pk) != 0) {
    mpz_clear(server_pk); 
    return -1;
	}
	fprintf(stderr, "Client: Server public key received successfully\n");
	
	/* send client pk */
	fprintf(stderr, "Client: Sending public key...\n");
	if (sendPublicKey(sockfd, client_dh_key.PK) != 0) {
    mpz_clear(server_pk); 
    return -1;
	}
	fprintf(stderr, "Client: Public key sent successfully\n");

	// derive shared secret 
	fprintf(stderr, "Client: Deriving shared secret...\n");
	unsigned char shared_secret[KEY_SIZE * 2];
	if (dhFinal(client_dh_key.SK, client_dh_key.PK, server_pk, shared_secret, sizeof(shared_secret)) != 0) {
		fprintf(stderr, "Client: Failed to derive shared secret\n");
		mpz_clear(server_pk);
		return -1;
	}
	fprintf(stderr, "Client: Shared secret derived successfully\n");
	
	// store shared secret and clear unused field
	memcpy(shared_key, shared_secret, sizeof(shared_secret));
	memset(shared_secret, 0, sizeof(shared_secret));

	mpz_clear(server_pk);
	
	// init crypto
	fprintf(stderr, "Client: Initializing encryption...\n");
	if (init_crypto() != 0) {
		fprintf(stderr, "Client: Failed to initialize crypto\n");
		return -1;
	}
	fprintf(stderr, "Client: Secure channel established\n");
	
	return 0;
}

static int shutdownNetwork()
{
	cleanup_crypto();
	
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

// init enc/dec contexts
static int init_crypto()
{
	// generate random IV
	if (RAND_bytes(iv, IV_SIZE) != 1) {
		fprintf(stderr, "Failed to generate secure random IV\n");
		return -1;
	}
	
	fprintf(stderr, "IV generated: ");
	for (int i = 0; i < 4; i++) {
		fprintf(stderr, "%02x", iv[i]);
	}
	fprintf(stderr, "...\n");
	
	// IV exchange
	if (isclient) {
		fprintf(stderr, "Client: Sending IV...\n");
		if (send(sockfd, iv, IV_SIZE, 0) != IV_SIZE) {
			fprintf(stderr, "Failed to send IV\n");
			return -1;
		}
		fprintf(stderr, "Client: IV sent successfully\n");
	} else {
		fprintf(stderr, "Server: Receiving IV...\n");
		if (recv(sockfd, iv, IV_SIZE, 0) != IV_SIZE) {
			fprintf(stderr, "Failed to receive IV\n");
			return -1;
		}
		fprintf(stderr, "Server: IV received: ");
		for (int i = 0; i < 4; i++) {
			fprintf(stderr, "%02x", iv[i]);
		}
		fprintf(stderr, "...\n");
	}
	
	// create aes_256_ctr contexts

	enc_ctx = EVP_CIPHER_CTX_new();
	if (enc_ctx == NULL) {
		fprintf(stderr, "Failed to create encryption context\n");
		return -1;
	}
	
	if (EVP_EncryptInit_ex(enc_ctx, EVP_aes_256_ctr(), NULL, shared_key, iv) != 1) {
		fprintf(stderr, "Failed to initialize encryption\n");
		EVP_CIPHER_CTX_free(enc_ctx);
		return -1;
	}
	fprintf(stderr, "AES-256-CTR encryption initialized\n");
	
	dec_ctx = EVP_CIPHER_CTX_new();
	if (dec_ctx == NULL) {
		fprintf(stderr, "Failed to create decryption context\n");
		EVP_CIPHER_CTX_free(enc_ctx);
		return -1;
	}
	
	if (EVP_DecryptInit_ex(dec_ctx, EVP_aes_256_ctr(), NULL, shared_key, iv) != 1) {
		fprintf(stderr, "Failed to initialize decryption\n");
		EVP_CIPHER_CTX_free(enc_ctx);
		EVP_CIPHER_CTX_free(dec_ctx);
		return -1;
	}
	fprintf(stderr, "AES-256-CTR decryption initialized\n");
	
	return 0;
}

// clean up enc/dec contexts
static void cleanup_crypto()
{
	if (enc_ctx) {
		EVP_CIPHER_CTX_free(enc_ctx);
		enc_ctx = NULL;
	}
	
	if (dec_ctx) {
		EVP_CIPHER_CTX_free(dec_ctx);
		dec_ctx = NULL;
	}
	
	memset(shared_key, 0, sizeof(shared_key));
	memset(iv, 0, sizeof(iv));
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;   /* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	size_t len = g_utf8_strlen(message,-1);
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */
	ssize_t nbytes;
	if ((nbytes = send(sockfd,message,len,0)) == -1)
		error("send failed");

	tsappend(message,NULL,1);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{
	size_t maxlen = 512;
	char msg[maxlen+2]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1) {
		if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}
		char* m = malloc(maxlen+2);
		memcpy(m,msg,nbytes);
		if (m[nbytes-1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;
		g_main_context_invoke(NULL,shownewmessage,(gpointer)m);
	}
	return 0;
}
