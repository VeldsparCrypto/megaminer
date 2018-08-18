//
//  main.c
//  megaminer
//
//  Created by Adrian Herridge on 08/08/2018.
//  Copyright © 2018 Veldspar. All rights reserved.
//

/*
 *  All the veldspar defines go here.
 */

#ifdef __linux__
#define __POSIX_OS__
#elif __APPLE__
#define __POSIX_OS__
#endif // __linux__

#ifndef __POSIX_OS__
#define _CRT_RAND_S 
#endif

/*
 * sha512.c - mbed TLS (formerly known as PolarSSL) implementation of SHA512
 *
 * Modifications Copyright 2017 Google Inc.
 * Modifications Author: Joe Richey (joerichey@google.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
/*
 *  FIPS-180-2 compliant SHA-512 implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The SHA-512 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */

#include <stddef.h>
#include <stdint.h>

#define SHA512_DIGEST_LENGTH 64

extern void SHA512(const uint8_t* in, size_t n,
                   uint8_t out[SHA512_DIGEST_LENGTH]);

// Zero the memory pointed to by v; this will not be optimized away.
extern void secure_wipe(uint8_t* v, uint32_t n);

#include <string.h>  // (memset_s or explicit_bzero if available)

#if defined(_MSC_VER) || defined(__WATCOMC__)
#define UL64(x) x##ui64
#else
#define UL64(x) x##ULL
#endif

/* We either use dedicated memory clearing functions or volatile dereference. */
void secure_wipe(uint8_t *v, uint32_t n) {
#if defined memset_s
    memset_s(v, n, 0, n);
#elif defined explicit_bzero
    explicit_bzero(v, n);
#else
    volatile uint8_t *p = v;
    while (n--) *p++ = 0;
#endif
}

/*
 * SHA-512 context structure
 */
typedef struct {
    uint64_t total[2];         /*!< number of bytes processed  */
    uint64_t state[8];         /*!< intermediate digest state  */
    unsigned char buffer[128]; /*!< data block being processed */
} mbedtls_sha512_context;

/*
 * 64-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT64_BE
#define GET_UINT64_BE(n, b, i)                                              \
{                                                                         \
(n) = ((uint64_t)(b)[(i)] << 56) | ((uint64_t)(b)[(i) + 1] << 48) |     \
((uint64_t)(b)[(i) + 2] << 40) | ((uint64_t)(b)[(i) + 3] << 32) | \
((uint64_t)(b)[(i) + 4] << 24) | ((uint64_t)(b)[(i) + 5] << 16) | \
((uint64_t)(b)[(i) + 6] << 8) | ((uint64_t)(b)[(i) + 7]);         \
}
#endif /* GET_UINT64_BE */

#ifndef PUT_UINT64_BE
#define PUT_UINT64_BE(n, b, i)                 \
{                                            \
(b)[(i)] = (unsigned char)((n) >> 56);     \
(b)[(i) + 1] = (unsigned char)((n) >> 48); \
(b)[(i) + 2] = (unsigned char)((n) >> 40); \
(b)[(i) + 3] = (unsigned char)((n) >> 32); \
(b)[(i) + 4] = (unsigned char)((n) >> 24); \
(b)[(i) + 5] = (unsigned char)((n) >> 16); \
(b)[(i) + 6] = (unsigned char)((n) >> 8);  \
(b)[(i) + 7] = (unsigned char)((n));       \
}
#endif /* PUT_UINT64_BE */

static void mbedtls_sha512_init(mbedtls_sha512_context *ctx) {
    memset(ctx, 0, sizeof(mbedtls_sha512_context));
}

/*
 * SHA-512 context setup
 */
static void mbedtls_sha512_starts(mbedtls_sha512_context *ctx) {
    ctx->total[0] = 0;
    ctx->total[1] = 0;
    
    ctx->state[0] = UL64(0x6A09E667F3BCC908);
    ctx->state[1] = UL64(0xBB67AE8584CAA73B);
    ctx->state[2] = UL64(0x3C6EF372FE94F82B);
    ctx->state[3] = UL64(0xA54FF53A5F1D36F1);
    ctx->state[4] = UL64(0x510E527FADE682D1);
    ctx->state[5] = UL64(0x9B05688C2B3E6C1F);
    ctx->state[6] = UL64(0x1F83D9ABFB41BD6B);
    ctx->state[7] = UL64(0x5BE0CD19137E2179);
}

/*
 * Round constants
 */
static const uint64_t K[80] = {
    UL64(0x428A2F98D728AE22), UL64(0x7137449123EF65CD),
    UL64(0xB5C0FBCFEC4D3B2F), UL64(0xE9B5DBA58189DBBC),
    UL64(0x3956C25BF348B538), UL64(0x59F111F1B605D019),
    UL64(0x923F82A4AF194F9B), UL64(0xAB1C5ED5DA6D8118),
    UL64(0xD807AA98A3030242), UL64(0x12835B0145706FBE),
    UL64(0x243185BE4EE4B28C), UL64(0x550C7DC3D5FFB4E2),
    UL64(0x72BE5D74F27B896F), UL64(0x80DEB1FE3B1696B1),
    UL64(0x9BDC06A725C71235), UL64(0xC19BF174CF692694),
    UL64(0xE49B69C19EF14AD2), UL64(0xEFBE4786384F25E3),
    UL64(0x0FC19DC68B8CD5B5), UL64(0x240CA1CC77AC9C65),
    UL64(0x2DE92C6F592B0275), UL64(0x4A7484AA6EA6E483),
    UL64(0x5CB0A9DCBD41FBD4), UL64(0x76F988DA831153B5),
    UL64(0x983E5152EE66DFAB), UL64(0xA831C66D2DB43210),
    UL64(0xB00327C898FB213F), UL64(0xBF597FC7BEEF0EE4),
    UL64(0xC6E00BF33DA88FC2), UL64(0xD5A79147930AA725),
    UL64(0x06CA6351E003826F), UL64(0x142929670A0E6E70),
    UL64(0x27B70A8546D22FFC), UL64(0x2E1B21385C26C926),
    UL64(0x4D2C6DFC5AC42AED), UL64(0x53380D139D95B3DF),
    UL64(0x650A73548BAF63DE), UL64(0x766A0ABB3C77B2A8),
    UL64(0x81C2C92E47EDAEE6), UL64(0x92722C851482353B),
    UL64(0xA2BFE8A14CF10364), UL64(0xA81A664BBC423001),
    UL64(0xC24B8B70D0F89791), UL64(0xC76C51A30654BE30),
    UL64(0xD192E819D6EF5218), UL64(0xD69906245565A910),
    UL64(0xF40E35855771202A), UL64(0x106AA07032BBD1B8),
    UL64(0x19A4C116B8D2D0C8), UL64(0x1E376C085141AB53),
    UL64(0x2748774CDF8EEB99), UL64(0x34B0BCB5E19B48A8),
    UL64(0x391C0CB3C5C95A63), UL64(0x4ED8AA4AE3418ACB),
    UL64(0x5B9CCA4F7763E373), UL64(0x682E6FF3D6B2B8A3),
    UL64(0x748F82EE5DEFB2FC), UL64(0x78A5636F43172F60),
    UL64(0x84C87814A1F0AB72), UL64(0x8CC702081A6439EC),
    UL64(0x90BEFFFA23631E28), UL64(0xA4506CEBDE82BDE9),
    UL64(0xBEF9A3F7B2C67915), UL64(0xC67178F2E372532B),
    UL64(0xCA273ECEEA26619C), UL64(0xD186B8C721C0C207),
    UL64(0xEADA7DD6CDE0EB1E), UL64(0xF57D4F7FEE6ED178),
    UL64(0x06F067AA72176FBA), UL64(0x0A637DC5A2C898A6),
    UL64(0x113F9804BEF90DAE), UL64(0x1B710B35131C471B),
    UL64(0x28DB77F523047D84), UL64(0x32CAAB7B40C72493),
    UL64(0x3C9EBE0A15C9BEBC), UL64(0x431D67C49C100D4C),
    UL64(0x4CC5D4BECB3E42B6), UL64(0x597F299CFC657E2A),
    UL64(0x5FCB6FAB3AD6FAEC), UL64(0x6C44198C4A475817)};

static void mbedtls_sha512_process(mbedtls_sha512_context *ctx,
                                   const unsigned char data[128]) {
    int i;
    uint64_t temp1, temp2, W[80];
    uint64_t A, B, C, D, E, F, G, H;
    
#define SHR(x, n) (x >> n)
#define ROTR(x, n) (SHR(x, n) | (x << (64 - n)))
    
#define S0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7))
#define S1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6))
    
#define S2(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S3(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
    
#define F0(x, y, z) ((x & y) | (z & (x | y)))
#define F1(x, y, z) (z ^ (x & (y ^ z)))
    
#define P(a, b, c, d, e, f, g, h, x, K)      \
{                                          \
temp1 = h + S3(e) + F1(e, f, g) + K + x; \
temp2 = S2(a) + F0(a, b, c);             \
d += temp1;                              \
h = temp1 + temp2;                       \
}
    
    for (i = 0; i < 16; i++) {
        GET_UINT64_BE(W[i], data, i << 3);
    }
    
    for (; i < 80; i++) {
        W[i] = S1(W[i - 2]) + W[i - 7] + S0(W[i - 15]) + W[i - 16];
    }
    
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];
    i = 0;
    
    do {
        P(A, B, C, D, E, F, G, H, W[i], K[i]);
        i++;
        P(H, A, B, C, D, E, F, G, W[i], K[i]);
        i++;
        P(G, H, A, B, C, D, E, F, W[i], K[i]);
        i++;
        P(F, G, H, A, B, C, D, E, W[i], K[i]);
        i++;
        P(E, F, G, H, A, B, C, D, W[i], K[i]);
        i++;
        P(D, E, F, G, H, A, B, C, W[i], K[i]);
        i++;
        P(C, D, E, F, G, H, A, B, W[i], K[i]);
        i++;
        P(B, C, D, E, F, G, H, A, W[i], K[i]);
        i++;
    } while (i < 80);
    
    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
    ctx->state[5] += F;
    ctx->state[6] += G;
    ctx->state[7] += H;
}

/*
 * SHA-512 process buffer
 */
static void mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                                  const unsigned char *input, size_t ilen) {
    size_t fill;
    unsigned int left;
    
    if (ilen == 0) return;
    
    left = (unsigned int)(ctx->total[0] & 0x7F);
    fill = 128 - left;
    
    ctx->total[0] += (uint64_t)ilen;
    
    if (ctx->total[0] < (uint64_t)ilen) ctx->total[1]++;
    
    if (left && ilen >= fill) {
        memcpy((void *)(ctx->buffer + left), input, fill);
        mbedtls_sha512_process(ctx, ctx->buffer);
        input += fill;
        ilen -= fill;
        left = 0;
    }
    
    while (ilen >= 128) {
        mbedtls_sha512_process(ctx, input);
        input += 128;
        ilen -= 128;
    }
    
    if (ilen > 0) memcpy((void *)(ctx->buffer + left), input, ilen);
}

static const unsigned char sha512_padding[128] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/*
 * SHA-512 final digest
 */
static void mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                                  unsigned char output[64]) {
    size_t last, padn;
    uint64_t high, low;
    unsigned char msglen[16];
    
    high = (ctx->total[0] >> 61) | (ctx->total[1] << 3);
    low = (ctx->total[0] << 3);
    
    PUT_UINT64_BE(high, msglen, 0);
    PUT_UINT64_BE(low, msglen, 8);
    
    last = (size_t)(ctx->total[0] & 0x7F);
    padn = (last < 112) ? (112 - last) : (240 - last);
    
    mbedtls_sha512_update(ctx, sha512_padding, padn);
    mbedtls_sha512_update(ctx, msglen, 16);
    
    PUT_UINT64_BE(ctx->state[0], output, 0);
    PUT_UINT64_BE(ctx->state[1], output, 8);
    PUT_UINT64_BE(ctx->state[2], output, 16);
    PUT_UINT64_BE(ctx->state[3], output, 24);
    PUT_UINT64_BE(ctx->state[4], output, 32);
    PUT_UINT64_BE(ctx->state[5], output, 40);
    PUT_UINT64_BE(ctx->state[6], output, 48);
    PUT_UINT64_BE(ctx->state[7], output, 56);
}

/*
 * output = SHA-512( input buffer )
 */
void SHA512(const uint8_t *in, size_t n, uint8_t out[SHA512_DIGEST_LENGTH]) {
    mbedtls_sha512_context ctx;
    
    mbedtls_sha512_init(&ctx);
    mbedtls_sha512_starts(&ctx);
    mbedtls_sha512_update(&ctx, in, n);
    mbedtls_sha512_finish(&ctx, out);
    secure_wipe((uint8_t *)&ctx, sizeof(ctx));
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
#include <locale>
#endif

#pragma GCC diagnostic ignored "-Wwrite-strings"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef _WIN32
#pragma warning(disable:4996)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#elif _LINUX
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#elif __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <netdb.h>
#include <fcntl.h>
#elif __FreeBSD__
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#elif __APPLE__
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#else
#error Platform not suppoted.
#endif

/*
 Gets the offset of one string in another string
 */
int str_index_of(const char *a, char *b)
{
    char *offset = (char*)strstr(a, b);
    return offset - a;
}

/*
 Checks if one string contains another string
 */
int str_contains(const char *haystack, const char *needle)
{
    char *pos = (char*)strstr(haystack, needle);
    if(pos)
        return 1;
    else
        return 0;
}

/*
 Removes last character from string
 */
char* trim_end(char *string, char to_trim)
{
    char last_char = string[strlen(string) -1];
    if(last_char == to_trim)
    {
        char *new_string = string;
        new_string[strlen(string) - 1] = 0;
        return new_string;
    }
    else
    {
        return string;
    }
}

/*
 Concecates two strings, a wrapper for strcat from string.h, handles the resizing and copying
 */
char* str_cat(char *a, char *b)
{
    char *target = (char*)malloc(strlen(a) + strlen(b) + 1);
    strcpy(target, a);
    strcat(target, b);
    return target;
}

/*
 Converts an integer value to its hex character
 */
char to_hex(char code)
{
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

/*
 URL encodes a string
 */
char *urlencode(char *str)
{
    char *pstr = str, *buf = (char*)malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr)
    {
        if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
            *pbuf++ = *pstr;
        else if (*pstr == ' ')
            *pbuf++ = '+';
        else
            *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

/*
 Replacement for the string.h strndup, fixes a bug
 */
char *str_ndup (const char *str, size_t max)
{
    size_t len = strnlen (str, max);
    char *res = (char*)malloc (len + 1);
    if (res)
    {
        memcpy (res, str, len);
        res[len] = '\0';
    }
    return res;
}

/*
 Replacement for the string.h strdup, fixes a bug
 */
char *str_dup(const char *src)
{
    char *tmp = (char*)malloc(strlen(src) + 1);
    if(tmp)
        strcpy(tmp, src);
    return tmp;
}

/*
 Search and replace a string with another string , in a string
 */
char *str_replace(char *search , char *replace , char *subject)
{
    char  *p = NULL , *old = NULL , *new_subject = NULL ;
    int c = 0 , search_size;
    search_size = strlen(search);
    for(p = strstr(subject , search) ; p != NULL ; p = strstr(p + search_size , search))
    {
        c++;
    }
    c = ( strlen(replace) - search_size )*c + strlen(subject);
    new_subject = (char*)malloc( c );
    strcpy(new_subject , "");
    old = subject;
    for(p = strstr(subject , search) ; p != NULL ; p = strstr(p + search_size , search))
    {
        strncpy(new_subject + strlen(new_subject) , old , p - old);
        strcpy(new_subject + strlen(new_subject) , replace);
        old = p + search_size;
    }
    strcpy(new_subject + strlen(new_subject) , old);
    return new_subject;
}

/*
 Get's all characters until '*until' has been found
 */
char* get_until(char *haystack, char *until)
{
    int offset = str_index_of(haystack, until);
    return str_ndup(haystack, offset);
}


/* decodeblock - decode 4 '6-bit' characters into 3 8-bit binary bytes */
void decodeblock(unsigned char in[], char *clrstr)
{
    unsigned char out[4];
    out[0] = in[0] << 2 | in[1] >> 4;
    out[1] = in[1] << 4 | in[2] >> 2;
    out[2] = in[2] << 6 | in[3] >> 0;
    out[3] = '\0';
    strncat((char *)clrstr, (char *)out, sizeof(out));
}

/*
 Decodes a Base64 string
 */
char* base64_decode(char *b64src)
{
    char *clrdst = (char*)malloc( ((strlen(b64src) - 1) / 3 ) * 4 + 4 + 50);
    char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int c, phase, i;
    unsigned char in[4];
    char *p;
    clrdst[0] = '\0';
    phase = 0; i=0;
    while(b64src[i])
    {
        c = (int) b64src[i];
        if(c == '=')
        {
            decodeblock(in, clrdst);
            break;
        }
        p = strchr(b64, c);
        if(p)
        {
            in[phase] = p - b64;
            phase = (phase + 1) % 4;
            if(phase == 0)
            {
                decodeblock(in, clrdst);
                in[0]=in[1]=in[2]=in[3]=0;
            }
        }
        i++;
    }
    clrdst = (char*)realloc(clrdst, strlen(clrdst) + 1);
    return clrdst;
}

/* encodeblock - encode 3 8-bit binary bytes as 4 '6-bit' characters */
void encodeblock( unsigned char in[], char b64str[], int len )
{
    char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char out[5];
    out[0] = b64[ in[0] >> 2 ];
    out[1] = b64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? b64[ ((in[1] & 0x0f) << 2) |
                                            ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? b64[ in[2] & 0x3f ] : '=');
    out[4] = '\0';
    strncat((char *)b64str, (char *)out, sizeof(out));
}

/*
 Encodes a string with Base64
 */
char* base64_encode(char *clrstr)
{
    char *b64dst = (char*)malloc(strlen(clrstr) + 50);
    char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char in[3];
    int i, len = 0;
    int j = 0;
    
    b64dst[0] = '\0';
    while(clrstr[j])
    {
        len = 0;
        for(i=0; i<3; i++)
        {
            in[i] = (unsigned char) clrstr[j];
            if(clrstr[j])
            {
                len++; j++;
            }
            else in[i] = 0;
        }
        if( len )
        {
            encodeblock( in, b64dst, len );
        }
    }
    b64dst = (char*)realloc(b64dst, strlen(b64dst) + 1);
    return b64dst;
}

/*
 http-client-c
 Copyright (C) 2012-2013  Swen Kooij
 
 This file is part of http-client-c.
 http-client-c is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 http-client-c is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with http-client-c. If not, see <http://www.gnu.org/licenses/>.
 Warning:
 This library does not tend to work that stable nor does it fully implent the
 standards described by IETF. For more information on the precise implentation of the
 Hyper Text Transfer Protocol:
 
 http://www.ietf.org/rfc/rfc2616.txt
 */

/*
 Represents an url
 */
struct parsed_url
{
    char *uri;                    /* mandatory */
    char *scheme;               /* mandatory */
    char *host;                 /* mandatory */
    char *ip;                     /* mandatory */
    char *port;                 /* optional */
    char *path;                 /* optional */
    char *query;                /* optional */
    char *fragment;             /* optional */
    char *username;             /* optional */
    char *password;             /* optional */
};

/*
 Free memory of parsed url
 */
void parsed_url_free(struct parsed_url *purl)
{
    if ( NULL != purl )
    {
        if ( NULL != purl->scheme ) free(purl->scheme);
        if ( NULL != purl->host ) free(purl->host);
        if ( NULL != purl->port ) free(purl->port);
        if ( NULL != purl->path )  free(purl->path);
        if ( NULL != purl->query ) free(purl->query);
        if ( NULL != purl->fragment ) free(purl->fragment);
        if ( NULL != purl->username ) free(purl->username);
        if ( NULL != purl->password ) free(purl->password);
        free(purl);
    }
}

/*
 Retrieves the IP adress of a hostname
 */
char* hostname_to_ip(char *hostname)
{
    char *ip = "0.0.0.0";
    struct hostent *h;
    if ((h=gethostbyname(hostname)) == NULL)
    {
        printf("gethostbyname");
        return NULL;
    }
    return inet_ntoa(*((struct in_addr *)h->h_addr));
}

/*
 Check whether the character is permitted in scheme string
 */
int is_scheme_char(int c)
{
    return (!isalpha(c) && '+' != c && '-' != c && '.' != c) ? 0 : 1;
}

/*
 Parses a specified URL and returns the structure named 'parsed_url'
 Implented according to:
 RFC 1738 - http://www.ietf.org/rfc/rfc1738.txt
 RFC 3986 -  http://www.ietf.org/rfc/rfc3986.txt
 */
struct parsed_url *parse_url(const char *url)
{
    
    /* Define variable */
    struct parsed_url *purl;
    const char *tmpstr;
    const char *curstr;
    int len;
    int i;
    int userpass_flag;
    int bracket_flag;
    
    /* Allocate the parsed url storage */
    purl = (struct parsed_url*)malloc(sizeof(struct parsed_url));
    if ( NULL == purl )
    {
        return NULL;
    }
    purl->scheme = NULL;
    purl->host = NULL;
    purl->port = NULL;
    purl->path = NULL;
    purl->query = NULL;
    purl->fragment = NULL;
    purl->username = NULL;
    purl->password = NULL;
    curstr = url;
    
    /*
     * <scheme>:<scheme-specific-part>
     * <scheme> := [a-z\+\-\.]+
     *             upper case = lower case for resiliency
     */
    /* Read scheme */
    tmpstr = strchr(curstr, ':');
    if ( NULL == tmpstr )
    {
        parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
        
        return NULL;
    }
    
    /* Get the scheme length */
    len = tmpstr - curstr;
    
    /* Check restrictions */
    for ( i = 0; i < len; i++ )
    {
        if (is_scheme_char(curstr[i]) == 0)
        {
            /* Invalid format */
            parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
            return NULL;
        }
    }
    /* Copy the scheme to the storage */
    purl->scheme = (char*)malloc(sizeof(char) * (len + 1));
    if ( NULL == purl->scheme )
    {
        parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
        
        return NULL;
    }
    
    (void)strncpy(purl->scheme, curstr, len);
    purl->scheme[len] = '\0';
    
    /* Make the character to lower if it is upper case. */
    for ( i = 0; i < len; i++ )
    {
        purl->scheme[i] = tolower(purl->scheme[i]);
    }
    
    /* Skip ':' */
    tmpstr++;
    curstr = tmpstr;
    
    /*
     * //<user>:<password>@<host>:<port>/<url-path>
     * Any ":", "@" and "/" must be encoded.
     */
    /* Eat "//" */
    for ( i = 0; i < 2; i++ )
    {
        if ( '/' != *curstr )
        {
            parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
            return NULL;
        }
        curstr++;
    }
    
    /* Check if the user (and password) are specified. */
    userpass_flag = 0;
    tmpstr = curstr;
    while ( '\0' != *tmpstr )
    {
        if ( '@' == *tmpstr )
        {
            /* Username and password are specified */
            userpass_flag = 1;
            break;
        }
        else if ( '/' == *tmpstr )
        {
            /* End of <host>:<port> specification */
            userpass_flag = 0;
            break;
        }
        tmpstr++;
    }
    
    /* User and password specification */
    tmpstr = curstr;
    if ( userpass_flag )
    {
        /* Read username */
        while ( '\0' != *tmpstr && ':' != *tmpstr && '@' != *tmpstr )
        {
            tmpstr++;
        }
        len = tmpstr - curstr;
        purl->username = (char*)malloc(sizeof(char) * (len + 1));
        if ( NULL == purl->username )
        {
            parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
            return NULL;
        }
        (void)strncpy(purl->username, curstr, len);
        purl->username[len] = '\0';
        
        /* Proceed current pointer */
        curstr = tmpstr;
        if ( ':' == *curstr )
        {
            /* Skip ':' */
            curstr++;
            
            /* Read password */
            tmpstr = curstr;
            while ( '\0' != *tmpstr && '@' != *tmpstr )
            {
                tmpstr++;
            }
            len = tmpstr - curstr;
            purl->password = (char*)malloc(sizeof(char) * (len + 1));
            if ( NULL == purl->password )
            {
                parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
                return NULL;
            }
            (void)strncpy(purl->password, curstr, len);
            purl->password[len] = '\0';
            curstr = tmpstr;
        }
        /* Skip '@' */
        if ( '@' != *curstr )
        {
            parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
            return NULL;
        }
        curstr++;
    }
    
    if ( '[' == *curstr )
    {
        bracket_flag = 1;
    }
    else
    {
        bracket_flag = 0;
    }
    /* Proceed on by delimiters with reading host */
    tmpstr = curstr;
    while ( '\0' != *tmpstr ) {
        if ( bracket_flag && ']' == *tmpstr )
        {
            /* End of IPv6 address. */
            tmpstr++;
            break;
        }
        else if ( !bracket_flag && (':' == *tmpstr || '/' == *tmpstr) )
        {
            /* Port number is specified. */
            break;
        }
        tmpstr++;
    }
    len = tmpstr - curstr;
    purl->host = (char*)malloc(sizeof(char) * (len + 1));
    if ( NULL == purl->host || len <= 0 )
    {
        parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
        return NULL;
    }
    (void)strncpy(purl->host, curstr, len);
    purl->host[len] = '\0';
    curstr = tmpstr;
    
    /* Is port number specified? */
    if ( ':' == *curstr )
    {
        curstr++;
        /* Read port number */
        tmpstr = curstr;
        while ( '\0' != *tmpstr && '/' != *tmpstr )
        {
            tmpstr++;
        }
        len = tmpstr - curstr;
        purl->port = (char*)malloc(sizeof(char) * (len + 1));
        if ( NULL == purl->port )
        {
            parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
            return NULL;
        }
        (void)strncpy(purl->port, curstr, len);
        purl->port[len] = '\0';
        curstr = tmpstr;
    }
    else
    {
        purl->port = "80";
    }
    
    /* Get ip */
    char *ip = hostname_to_ip(purl->host);
    purl->ip = ip;
    
    /* Set uri */
    purl->uri = (char*)url;
    
    /* End of the string */
    if ( '\0' == *curstr )
    {
        return purl;
    }
    
    /* Skip '/' */
    if ( '/' != *curstr )
    {
        parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
        return NULL;
    }
    curstr++;
    
    /* Parse path */
    tmpstr = curstr;
    while ( '\0' != *tmpstr && '#' != *tmpstr  && '?' != *tmpstr )
    {
        tmpstr++;
    }
    len = tmpstr - curstr;
    purl->path = (char*)malloc(sizeof(char) * (len + 1));
    if ( NULL == purl->path )
    {
        parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
        return NULL;
    }
    (void)strncpy(purl->path, curstr, len);
    purl->path[len] = '\0';
    curstr = tmpstr;
    
    /* Is query specified? */
    if ( '?' == *curstr )
    {
        /* Skip '?' */
        curstr++;
        /* Read query */
        tmpstr = curstr;
        while ( '\0' != *tmpstr && '#' != *tmpstr )
        {
            tmpstr++;
        }
        len = tmpstr - curstr;
        purl->query = (char*)malloc(sizeof(char) * (len + 1));
        if ( NULL == purl->query )
        {
            parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
            return NULL;
        }
        (void)strncpy(purl->query, curstr, len);
        purl->query[len] = '\0';
        curstr = tmpstr;
    }
    
    /* Is fragment specified? */
    if ( '#' == *curstr )
    {
        /* Skip '#' */
        curstr++;
        /* Read fragment */
        tmpstr = curstr;
        while ( '\0' != *tmpstr )
        {
            tmpstr++;
        }
        len = tmpstr - curstr;
        purl->fragment = (char*)malloc(sizeof(char) * (len + 1));
        if ( NULL == purl->fragment )
        {
            parsed_url_free(purl); fprintf(stderr, "Error on line %d (%s)\n", __LINE__, __FILE__);
            return NULL;
        }
        (void)strncpy(purl->fragment, curstr, len);
        purl->fragment[len] = '\0';
        curstr = tmpstr;
    }
    return purl;
}

/*
 http-client-c
 Copyright (C) 2012-2013  Swen Kooij
 This file is part of http-client-c.
 http-client-c is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 http-client-c is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with http-client-c. If not, see <http://www.gnu.org/licenses/>.
 Warning:
 This library does not tend to work that stable nor does it fully implent the
 standards described by IETF. For more information on the precise implentation of the
 Hyper Text Transfer Protocol:
 http://www.ietf.org/rfc/rfc2616.txt
 */

/*
 Prototype functions
 */
struct http_response* http_req(char *http_headers, struct parsed_url *purl);
struct http_response* http_get(char *url, char *custom_headers);
struct http_response* http_head(char *url, char *custom_headers);
struct http_response* http_post(char *url, char *custom_headers, char *post_data);


/*
 Represents an HTTP html response
 */
struct http_response
{
    struct parsed_url *request_uri;
    char *body;
    char *status_code;
    int status_code_int;
    char *status_text;
    char *request_headers;
    char *response_headers;
};

/*
 Handles redirect if needed for get requests
 */
struct http_response* handle_redirect_get(struct http_response* hresp, char* custom_headers)
{
    if(hresp->status_code_int > 300 && hresp->status_code_int < 399)
    {
        char *token = strtok(hresp->response_headers, "\r\n");
        while(token != NULL)
        {
            if(str_contains(token, "Location:"))
            {
                /* Extract url */
                char *location = str_replace("Location: ", "", token);
                return http_get(location, custom_headers);
            }
            token = strtok(NULL, "\r\n");
        }
    }
    else
    {
        /* We're not dealing with a redirect, just return the same structure */
        return hresp;
    }
    
    return NULL;
}

/*
 Handles redirect if needed for head requests
 */
struct http_response* handle_redirect_head(struct http_response* hresp, char* custom_headers)
{
    if(hresp->status_code_int > 300 && hresp->status_code_int < 399)
    {
        char *token = strtok(hresp->response_headers, "\r\n");
        while(token != NULL)
        {
            if(str_contains(token, "Location:"))
            {
                /* Extract url */
                char *location = str_replace("Location: ", "", token);
                return http_head(location, custom_headers);
            }
            token = strtok(NULL, "\r\n");
        }
    }
    else
    {
        /* We're not dealing with a redirect, just return the same structure */
        return hresp;
    }
    
    return NULL;
    
}

/*
 Handles redirect if needed for post requests
 */
struct http_response* handle_redirect_post(struct http_response* hresp, char* custom_headers, char *post_data)
{
    if(hresp->status_code_int > 300 && hresp->status_code_int < 399)
    {
        char *token = strtok(hresp->response_headers, "\r\n");
        while(token != NULL)
        {
            if(str_contains(token, "Location:"))
            {
                /* Extract url */
                char *location = str_replace("Location: ", "", token);
                return http_post(location, custom_headers, post_data);
            }
            token = strtok(NULL, "\r\n");
        }
    }
    else
    {
        /* We're not dealing with a redirect, just return the same structure */
        return hresp;
    }
    
    return NULL;
    
}

/*
 Makes a HTTP request and returns the response
 */
struct http_response* http_req(char *http_headers, struct parsed_url *purl)
{
    /* Parse url */
    if(purl == NULL)
    {
        printf("Unable to parse url");
        return NULL;
    }
    
    /* Declare variable */
    int sock;
    int tmpres;
    char buf[BUFSIZ+1];
    struct sockaddr_in *remote;
    
    /* Allocate memeory for htmlcontent */
    struct http_response *hresp = (struct http_response*)malloc(sizeof(struct http_response));
    if(hresp == NULL)
    {
        printf("Unable to allocate memory for htmlcontent.");
        return NULL;
    }
    hresp->body = NULL;
    hresp->request_headers = NULL;
    hresp->response_headers = NULL;
    hresp->status_code = NULL;
    hresp->status_text = NULL;
    
    /* Create TCP socket */
    if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        printf("Can't create TCP socket");
        return NULL;
    }
    
    /* Set remote->sin_addr.s_addr */
    remote = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in *));
    remote->sin_family = AF_INET;
    tmpres = inet_pton(AF_INET, "138.68.116.96", (void *)(&(remote->sin_addr.s_addr)));
    if( tmpres < 0)
    {
        printf("Can't set remote->sin_addr.s_addr");
        return NULL;
    }
    else if(tmpres == 0)
    {
        printf("Not a valid IP");
        return NULL;
    }
    remote->sin_port = htons(atoi(purl->port));
    
    /* set an agressive timeout policy */

    /* Connect */
    if(connect(sock, (struct sockaddr *)remote, sizeof(struct sockaddr)) < 0)
    {
        printf("Could not connect");
        return NULL;
    }
    
    /* Send headers to server */
    int sent = 0;
    while(sent < strlen(http_headers))
    {
        tmpres = send(sock, http_headers+sent, strlen(http_headers)-sent, 0);
        if(tmpres == -1)
        {
            printf("Can't send headers");
            return NULL;
        }
        sent += tmpres;
    }
    
    /* Recieve into response*/
    char *response = (char*)malloc(0);
    char BUF[BUFSIZ];
    size_t recived_len = 0;
    while((recived_len = recv(sock, BUF, BUFSIZ-1, 0)) > 0)
    {
        BUF[recived_len] = '\0';
        response = (char*)realloc(response, strlen(response) + strlen(BUF) + 1);
        sprintf(response, "%s%s", response, BUF);
    }
    if (recived_len < 0)
    {
        free(http_headers);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        printf("Unabel to recieve");
        return NULL;
    }
    
    /* Reallocate response */
    response = (char*)realloc(response, strlen(response) + 1);
    
    /* Close socket */
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    
    /* Parse status code and text */
    char *status_line = get_until(response, "\r\n");
    status_line = str_replace("HTTP/1.1 ", "", status_line);
    char *status_code = str_ndup(status_line, 4);
    status_code = str_replace(" ", "", status_code);
    char *status_text = str_replace(status_code, "", status_line);
    status_text = str_replace(" ", "", status_text);
    hresp->status_code = status_code;
    hresp->status_code_int = atoi(status_code);
    hresp->status_text = status_text;
    
    /* Parse response headers */
    char *headers = get_until(response, "\r\n\r\n");
    hresp->response_headers = headers;
    
    /* Assign request headers */
    hresp->request_headers = http_headers;
    
    /* Assign request url */
    hresp->request_uri = purl;
    
    /* Parse body */
    char *body = strstr(response, "\r\n\r\n");
    body = str_replace("\r\n\r\n", "", body);
    hresp->body = body;
    
    /* Return response */
    return hresp;
}

/*
 Makes a HTTP GET request to the given url
 */
struct http_response* http_get(char *url, char *custom_headers)
{
    /* Parse url */
    struct parsed_url *purl = parse_url(url);
    if(purl == NULL)
    {
        printf("Unable to parse url");
        return NULL;
    }
    
    /* Declare variable */
    char *http_headers = (char*)malloc(1024);
    
    /* Build query/headers */
    if(purl->path != NULL)
    {
        if(purl->query != NULL)
        {
            sprintf(http_headers, "GET /%s?%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->path, purl->query, purl->host);
        }
        else
        {
            sprintf(http_headers, "GET /%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->path, purl->host);
        }
    }
    else
    {
        if(purl->query != NULL)
        {
            sprintf(http_headers, "GET /?%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->query, purl->host);
        }
        else
        {
            sprintf(http_headers, "GET / HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->host);
        }
    }
    
    /* Handle authorisation if needed */
    if(purl->username != NULL)
    {
        /* Format username:password pair */
        char *upwd = (char*)malloc(1024);
        sprintf(upwd, "%s:%s", purl->username, purl->password);
        upwd = (char*)realloc(upwd, strlen(upwd) + 1);
        
        /* Base64 encode */
        char *base64 = base64_encode(upwd);
        
        /* Form header */
        char *auth_header = (char*)malloc(1024);
        sprintf(auth_header, "Authorization: Basic %s\r\n", base64);
        auth_header = (char*)realloc(auth_header, strlen(auth_header) + 1);
        
        /* Add to header */
        http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(auth_header) + 2);
        sprintf(http_headers, "%s%s", http_headers, auth_header);
    }
    
    /* Add custom headers, and close */
    if(custom_headers != NULL)
    {
        sprintf(http_headers, "%s%s\r\n", http_headers, custom_headers);
    }
    else
    {
        sprintf(http_headers, "%s\r\n", http_headers);
    }
    http_headers = (char*)realloc(http_headers, strlen(http_headers) + 1);
    
    /* Make request and return response */
    struct http_response *hresp = http_req(http_headers, purl);
    
    if (hresp == NULL) {
        return NULL;
    }
    
    /* Handle redirect */
    return handle_redirect_get(hresp, custom_headers);
}

/*
 Makes a HTTP POST request to the given url
 */
struct http_response* http_post(char *url, char *custom_headers, char *post_data)
{
    /* Parse url */
    struct parsed_url *purl = parse_url(url);
    if(purl == NULL)
    {
        printf("Unable to parse url");
        return NULL;
    }
    
    /* Declare variable */
    char *http_headers = (char*)malloc(1024);
    
    /* Build query/headers */
    if(purl->path != NULL)
    {
        if(purl->query != NULL)
        {
            sprintf(http_headers, "POST /%s?%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\nContent-Length:%zu\r\nContent-Type:application/x-www-form-urlencoded\r\n", purl->path, purl->query, purl->host, strlen(post_data));
        }
        else
        {
            sprintf(http_headers, "POST /%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\nContent-Length:%zu\r\nContent-Type:application/x-www-form-urlencoded\r\n", purl->path, purl->host, strlen(post_data));
        }
    }
    else
    {
        if(purl->query != NULL)
        {
            sprintf(http_headers, "POST /?%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\nContent-Length:%zu\r\nContent-Type:application/x-www-form-urlencoded\r\n", purl->query, purl->host, strlen(post_data));
        }
        else
        {
            sprintf(http_headers, "POST / HTTP/1.1\r\nHost:%s\r\nConnection:close\r\nContent-Length:%zu\r\nContent-Type:application/x-www-form-urlencoded\r\n", purl->host, strlen(post_data));
        }
    }
    
    /* Handle authorisation if needed */
    if(purl->username != NULL)
    {
        /* Format username:password pair */
        char *upwd = (char*)malloc(1024);
        sprintf(upwd, "%s:%s", purl->username, purl->password);
        upwd = (char*)realloc(upwd, strlen(upwd) + 1);
        
        /* Base64 encode */
        char *base64 = base64_encode(upwd);
        
        /* Form header */
        char *auth_header = (char*)malloc(1024);
        sprintf(auth_header, "Authorization: Basic %s\r\n", base64);
        auth_header = (char*)realloc(auth_header, strlen(auth_header) + 1);
        
        /* Add to header */
        http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(auth_header) + 2);
        sprintf(http_headers, "%s%s", http_headers, auth_header);
    }
    
    if(custom_headers != NULL)
    {
        sprintf(http_headers, "%s%s\r\n", http_headers, custom_headers);
        sprintf(http_headers, "%s\r\n%s", http_headers, post_data);
    }
    else
    {
        sprintf(http_headers, "%s\r\n%s", http_headers, post_data);
    }
    http_headers = (char*)realloc(http_headers, strlen(http_headers) + 1);
    
    /* Make request and return response */
    struct http_response *hresp = http_req(http_headers, purl);
    
    /* Handle redirect */
    return handle_redirect_post(hresp, custom_headers, post_data);
}

/*
 Makes a HTTP HEAD request to the given url
 */
struct http_response* http_head(char *url, char *custom_headers)
{
    /* Parse url */
    struct parsed_url *purl = parse_url(url);
    if(purl == NULL)
    {
        printf("Unable to parse url");
        return NULL;
    }
    
    /* Declare variable */
    char *http_headers = (char*)malloc(1024);
    
    /* Build query/headers */
    if(purl->path != NULL)
    {
        if(purl->query != NULL)
        {
            sprintf(http_headers, "HEAD /%s?%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->path, purl->query, purl->host);
        }
        else
        {
            sprintf(http_headers, "HEAD /%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->path, purl->host);
        }
    }
    else
    {
        if(purl->query != NULL)
        {
            sprintf(http_headers, "HEAD/?%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->query, purl->host);
        }
        else
        {
            sprintf(http_headers, "HEAD / HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->host);
        }
    }
    
    /* Handle authorisation if needed */
    if(purl->username != NULL)
    {
        /* Format username:password pair */
        char *upwd = (char*)malloc(1024);
        sprintf(upwd, "%s:%s", purl->username, purl->password);
        upwd = (char*)realloc(upwd, strlen(upwd) + 1);
        
        /* Base64 encode */
        char *base64 = base64_encode(upwd);
        
        /* Form header */
        char *auth_header = (char*)malloc(1024);
        sprintf(auth_header, "Authorization: Basic %s\r\n", base64);
        auth_header = (char*)realloc(auth_header, strlen(auth_header) + 1);
        
        /* Add to header */
        http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(auth_header) + 2);
        sprintf(http_headers, "%s%s", http_headers, auth_header);
    }
    
    if(custom_headers != NULL)
    {
        sprintf(http_headers, "%s%s\r\n", http_headers, custom_headers);
    }
    else
    {
        sprintf(http_headers, "%s\r\n", http_headers);
    }
    http_headers = (char*)realloc(http_headers, strlen(http_headers) + 1);
    
    /* Make request and return response */
    struct http_response *hresp = http_req(http_headers, purl);
    
    /* Handle redirect */
    return handle_redirect_head(hresp, custom_headers);
}

/*
 Do HTTP OPTIONs requests
 */
struct http_response* http_options(char *url)
{
    /* Parse url */
    struct parsed_url *purl = parse_url(url);
    if(purl == NULL)
    {
        printf("Unable to parse url");
        return NULL;
    }
    
    /* Declare variable */
    char *http_headers = (char*)malloc(1024);
    
    /* Build query/headers */
    if(purl->path != NULL)
    {
        if(purl->query != NULL)
        {
            sprintf(http_headers, "OPTIONS /%s?%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->path, purl->query, purl->host);
        }
        else
        {
            sprintf(http_headers, "OPTIONS /%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->path, purl->host);
        }
    }
    else
    {
        if(purl->query != NULL)
        {
            sprintf(http_headers, "OPTIONS/?%s HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->query, purl->host);
        }
        else
        {
            sprintf(http_headers, "OPTIONS / HTTP/1.1\r\nHost:%s\r\nConnection:close\r\n", purl->host);
        }
    }
    
    /* Handle authorisation if needed */
    if(purl->username != NULL)
    {
        /* Format username:password pair */
        char *upwd = (char*)malloc(1024);
        sprintf(upwd, "%s:%s", purl->username, purl->password);
        upwd = (char*)realloc(upwd, strlen(upwd) + 1);
        
        /* Base64 encode */
        char *base64 = base64_encode(upwd);
        
        /* Form header */
        char *auth_header = (char*)malloc(1024);
        sprintf(auth_header, "Authorization: Basic %s\r\n", base64);
        auth_header = (char*)realloc(auth_header, strlen(auth_header) + 1);
        
        /* Add to header */
        http_headers = (char*)realloc(http_headers, strlen(http_headers) + strlen(auth_header) + 2);
        sprintf(http_headers, "%s%s", http_headers, auth_header);
    }
    
    /* Build headers */
    sprintf(http_headers, "%s\r\n", http_headers);
    http_headers = (char*)realloc(http_headers, strlen(http_headers) + 1);
    
    /* Make request and return response */
    struct http_response *hresp = http_req(http_headers, purl);
    
    /* Handle redirect */
    return hresp;
}

/*
 Free memory of http_response
 */
void http_response_free(struct http_response *hresp)
{
    if(hresp != NULL)
    {
        if(hresp->request_uri != NULL) parsed_url_free(hresp->request_uri);
        if(hresp->body != NULL) free(hresp->body);
        if(hresp->status_code != NULL) free(hresp->status_code);
        if(hresp->status_text != NULL) free(hresp->status_text);
        if(hresp->request_headers != NULL) free(hresp->request_headers);
        if(hresp->response_headers != NULL) free(hresp->response_headers);
        free(hresp);
    }
}

// copy of apple's rng.  Very effective and quick

unsigned long bounded_rand(unsigned long max) {
#ifdef __POSIX_OS__
	unsigned long
    // max <= RAND_MAX < ULONG_MAX, so this is okay.
    num_bins = (unsigned long) max + 1,
    num_rand = (unsigned long) RAND_MAX + 1,
    bin_size = num_rand / num_bins,
    defect   = num_rand % num_bins;
    
    long x;
    do {
		x = random();        
    }
    // This is carefully written not to overflow
    while (num_rand - defect <= (unsigned long)x);
    
    // Truncated division is intentional
    return x/bin_size;
#else
	// shitty windows can't do anything right
	unsigned int    number;
	errno_t         err;
	err = rand_s(&number);
	if (err != 0)
	{
		printf("The rand_s function failed!\n");
		exit(0);
	}
	return  (unsigned long long)(((double)number / ((double)UINT_MAX + 1) * max) + 1);
#endif // __POSIX_OS__

}

#include <stdio.h>
#include "config.h"
#include <time.h>
#ifdef __POSIX_OS__
#include <pthread.h>
#include <unistd.h>
#endif

const char* address = NULL;

#ifdef __POSIX_OS__
void* miningThread(void *x_void_ptr) {
#else
DWORD WINAPI miningThread(LPVOID lpParam) {
#endif
    
    // where ore is a 1mb selection of random data (static char ore[] = {1,2,3,4 ... etc } )
    // beans is a 36kb buffer of 9000 "beans", of 4 bytes.
    // once a basic hash condition is met, we look for beans within the hash from the random selection made form the ore.
    
    const int maxRange = sizeof(ore) - 64;
    const int selectionSize = 8*64;
    
    char* immutableOre = malloc(sizeof(ore));
    memcpy(immutableOre, ore, sizeof(ore));
    
    char* threadCache = malloc(1000*1024);
    memset(threadCache, 0, 1000*1024);
    int cacheCount = 0;
    
    // so the miner basically has to loop constantly, hashing random points in the ore.
    while (1) {
        
        uint32_t value = 0;
        uint32_t segments[8];
        static uint32_t oreBlock = 0;
        static uint16_t minerVer = 2;

        // fetch 8 random 64 byte segments from within the ore
        uint8_t *selection = malloc(selectionSize);
        memset(selection, 0, selectionSize);
        
        for (int i = 0; i < 8; i++) {
            segments[i] = (uint32_t)bounded_rand(maxRange);
            memcpy(selection + (i*64), ((char*)immutableOre) + segments[i], 64);
        }
        
        // now hash it to see if we start within range
        uint8_t *hash = malloc(SHA512_DIGEST_LENGTH);
        memset(hash, 0, SHA512_DIGEST_LENGTH);
        SHA512(selection, selectionSize, hash);
        
        if (hash[0] == 255 && hash[1] >= (255-16)) {
            
            // through the gate, now to check for byte patterns, any match whatsoever is a pass
            for (int i=0; i < 9000; i++) {
                
                int beanPosition = i * 4;
                
                // now see if the first byte of the bean is in the hash;
                uint8_t *hashPtr = hash;
                while (memchr(hashPtr, beans[beanPosition], ((hash + SHA512_DIGEST_LENGTH) - hashPtr))) {
                    
                    hashPtr = memchr(hashPtr, beans[beanPosition], ((hash + SHA512_DIGEST_LENGTH) - hashPtr));
                    
                    if (beans[beanPosition+1] == hashPtr[1] && beans[beanPosition+2] == hashPtr[2] && beans[beanPosition+3] == hashPtr[3]) {
                        
                        if (beans_value[i] > value) {
                            value = beans_value[i];
                            break;
                        }
                        
                    }
                    
                    hashPtr++;
                    
                    if (hashPtr >= (((hash + SHA512_DIGEST_LENGTH) - 4))) {
                        break;
                    }
                    
                }
                
                
            }
            
        }
        
        if (value) {
            // we found a token, so create the address.
            char token[96];
            sprintf(token,"%08X-%04X-%08X-%08X-%08X-%08X-%08X-%08X-%08X-%08X-%08X", oreBlock, minerVer, value, segments[0], segments[1], segments[2], segments[3], segments[4], segments[5], segments[6], segments[7]);
            
            time_t timer;
            char buffer[26];
            struct tm* tm_info;
            
            time(&timer);
            tm_info = localtime(&timer);
            
            strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
            puts(buffer);
            
            printf("[%s] Found token: %s\n", buffer, token);
            printf("[%s] Value: %f\n", buffer, (((float)value) / 100.0f));
            
            // download the ore seed and generate the ore
            char registration[1024];
            memset(&registration, 0, 1024);
            sprintf(registration, "http://seed1.veldspar.co:14242/token/register?address=%s&token=%s", address, token);
            struct http_response* send = http_get(registration, NULL);
            if (send == NULL) {
                printf("Unable to send token registration to network.  Network may currently be offline.\nCaching the find and will retry submission later.  Do not close the miner of cache will be lost.\n");
                if (cacheCount < 999) {
                    memcpy(threadCache+(cacheCount*1024), registration, 1024);
                    cacheCount++;
                }
            } else {
                printf("Token sent to the network for registration.\n");
                if (strstr(send->body, "\"success\":true")) {
                    printf("Token successfully registered :) \n");
                } else {
                    printf("Token already registered :( \n");
                }
                if (cacheCount) {
                    while(cacheCount) {
                        char registration[1024];
                        memset(&registration, 0, 1024);
                        memcpy(&registration, threadCache+((cacheCount-1)*1024), 1024);
                        struct http_response* send = http_get(registration, NULL);
                        if (send == NULL) {
                            break;
                        } else {
                            printf("Token sent to the network for registration.\n");
                            if (strstr(send->body, "\"success\":true")) {
                                printf("Token successfully registered :) \n");
                            } else {
                                printf("Token already registered :( \n");
                            }
                        }
                        cacheCount--;
                        memset(threadCache+(cacheCount*1024), 0, 1024);
                    }
                }
            }
            
        }
        
        free(selection);
        free(hash);
        
    }
    
}

// seed for PRNG
unsigned long long rdtsc(){
#ifdef __arm__
    return (unsigned long long)(time(NULL) & 0xFFFF) | (getpid() << 16);
#else
#ifdef __POSIX_OS__
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
#else
	// win64 implementation 
	return (unsigned long long)GetTickCount();
#endif
#endif
}

int main(int argc, const char * argv[]) {
    
    // insert code here...
    printf("Veldspar MegaMiner v0.0.8 - Frankenstein's Monster Edition\n");
    printf("----------------------------------------------------------\n");
    printf("\n");
    
    int threadCount = 4;
    
    if (argc) {
        for (int idx=0; idx < argc; idx++) {
            if (strcmp(argv[idx], "--help") == 0) {
                printf("Commands\n");
                printf("--------\n");
                printf("--address       : Veldspar wallet address, looks like 'VE4DuSf92FRLE26qDXC2y1tyPdmKbk5XcbRg6VXGghxQAi'\n");
                printf("--threads       : Number of threads to abuse\n\n");
                exit(0);
            }
            if (strcmp(argv[idx], "--threads") == 0) {
                // now grab the parameter for threads if the argc is high enough
                if (idx+1 <= argc) {
                    threadCount = atoi(argv[idx+1]);
                }
            }
            if (strcmp(argv[idx], "--address") == 0) {
                // now grab the parameter for threads if the argc is high enough
                if (idx+1 <= argc) {
                    address = argv[idx+1];
                    
                    // I guess we should check the users haven't done something stupid!
                    if (address[0] != 'V' || address[1] != 'E') {
                        printf("Incorrect address specified.\n");
                        exit(0);
                    }
                    
                    if (strlen(address) != 46) {
                        printf("Incorrect address specified.\n");
                        exit(0);
                    }
                    
                }
            }
        }
    }
    
    if (address == NULL) {
        printf("No address specified.");
        exit(0);
    }
    
    printf("Setting up random seed\n");
    srand((uint32_t)rdtsc());
#ifdef __POSIX_OS__
    pthread_t threads[threadCount];
#else
	DWORD threadIDs[1024];
	HANDLE threads[1024];
#endif
    for (int i=0; i < threadCount; i++) {
        printf("Starting mining thread %i\n", i);
#ifdef __POSIX_OS__
        pthread_create(&threads[i], NULL, miningThread, NULL);
#else
		threads[i] = CreateThread(NULL, 0, miningThread, NULL, 0, &threadIDs[i]);
#endif
    }
    
    while(1) {
        //dirty, but it's 11pm.
#ifdef __POSIX_OS__
        sleep(10);
#else
		Sleep(10000);
#endif
    }
    
    return 0;
}

