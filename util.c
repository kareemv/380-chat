#include "util.h"
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <endian.h>
#include <string.h>

/* when reading long integers, never read more than this many bytes: */
#define MPZ_MAX_LEN 1024

/* Like read(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xread(int fd, void *buf, size_t nBytes)
{
	do {
		ssize_t n = read(fd, buf, nBytes);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && errno == EWOULDBLOCK) continue;
		if (n < 0) perror("read"), abort();
		buf = (char *)buf + n;
		nBytes -= n;
	} while (nBytes);
}

/* Like write(), but retry on EINTR and EWOULDBLOCK,
 * abort on other errors, and don't return early. */
void xwrite(int fd, const void *buf, size_t nBytes)
{
	do {
		ssize_t n = write(fd, buf, nBytes);
		if (n < 0 && errno == EINTR) continue;
		if (n < 0 && errno == EWOULDBLOCK) continue;
		if (n < 0) perror("write"), abort();
		buf = (const char *)buf + n;
		nBytes -= n;
	} while (nBytes);
}

size_t serialize_mpz(int fd, mpz_t x)
{
	/* format:
	 * +--------------------------------------------+---------------------------+
	 * | nB := numBytes(x) (little endian, 4 bytes) | bytes(x) (l.e., nB bytes) |
	 * +--------------------------------------------+---------------------------+
	 * */
	/* NOTE: for compatibility across different systems, we always write integers
	 * little endian byte order when serializing.  Note also that mpz_sizeinbase
	 * will return 1 if x is 0, so nB should always be the correct byte count. */
	size_t nB;
	unsigned char* buf = Z2BYTES(NULL,&nB,x);
	/* above has allocated memory for us, and stored the size in nB.  HOWEVER,
	 * if x was 0, then no allocation would be done, and buf will be NULL: */
	if (!buf) {
		nB = 1;
		buf = malloc(1);
		*buf = 0;
	}
	assert(nB < 1LU << 32); /* make sure it fits in 4 bytes */
	LE(nB);
	xwrite(fd,&nB_le,4);
	xwrite(fd,buf,nB);
	free(buf);
	return nB+4; /* total number of bytes written to fd */
}

int deserialize_mpz(mpz_t x, int fd)
{
	/* we assume buffer is formatted as above */
	uint32_t nB_le;
	xread(fd,&nB_le,4);
	size_t nB = le32toh(nB_le);
	if (nB > MPZ_MAX_LEN) return -1;
	unsigned char* buf = malloc(nB);
	xread(fd,buf,nB);
	BYTES2Z(x,buf,nB);
	return 0;
}

void sendPublicKey(int socket, mpz_t publicKey) {
	size_t keySize = mpz_sizeinbase(publicKey, 2) / 8 + 1; 
	unsigned char *keyBuffer = malloc(keySize);
	if (keyBuffer == NULL) {
			perror("Failed to allocate memory for public key buffer");
			return;
	}
	mpz_export(keyBuffer, NULL, 1, sizeof(unsigned char), 0, 0, publicKey); 
	if (xwrite(socket, keyBuffer, keySize) < 0) {
			perror("Failed to send public key");
	}
	free(keyBuffer);
}

void receivePublicKey(int socket, mpz_t publicKey) {
	size_t keySize;
	if (xread(socket, &keySize, sizeof(size_t)) != sizeof(size_t)) {
			perror("Failed to read key size");
			return;
	}
	unsigned char *keyBuffer = malloc(keySize); 
	if (keyBuffer == NULL) {
			perror("Failed to allocate memory for public key buffer");
			return;
	}
	if (xread(socket, keyBuffer, keySize) != keySize) {
			perror("Failed to read public key");
			free(keyBuffer);
			return;
	}
	mpz_import(publicKey, keySize, 1, sizeof(unsigned char), 0, 0, keyBuffer); 
	free(keyBuffer);
}