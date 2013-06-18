
#ifndef _SHA1_H_
#define _SHA1_H_

/* ================ sha1.h ================ */
/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/compat.h>
#include <linux/rbtree.h>
#include <crypto/hash.h>

#define SHA1_HASH_SIZE 20

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

typedef struct {
    unsigned char digest[SHA1_HASH_SIZE];
} sha1_digest;

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const unsigned char* data, uint32_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);
uint32_t cbc_crc32_le(const uint8_t *buf, int len);

/* int compsha1(unsigned char *buf1, unsigned char *buf2, int buf_size); */
/* ================ end of sha1.h ================ */

#endif
