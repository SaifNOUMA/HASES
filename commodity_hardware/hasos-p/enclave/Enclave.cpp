/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <math.h>
#include "Enclave.h"
#include "Enclave_t.h"
#include "tSgxSSL_api.h"

#define ADD_ENTROPY_SIZE	32

int sha256_i(uint8_t* message, size_t messagelen,
             uint8_t* hash, int counter)
{
    uint8_t prior_hash[messagelen + sizeof(counter)];

    memset(prior_hash, sizeof(prior_hash), 0);
    memcpy(prior_hash, message, messagelen);
    memcpy(prior_hash + messagelen, (uint8_t*) &counter, sizeof(counter));

    if (NULL == SHA256(prior_hash, sizeof(prior_hash), hash))                                           { return 0; }

    return 1;
}

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_uprint(buf);
}


int vprintf_cb(Stream_t stream, const char * fmt, va_list arg)
{
	char buf[BUFSIZ] = {'\0'};

	int res = vsnprintf(buf, BUFSIZ, fmt, arg);
	if (res >=0) {
		sgx_status_t sgx_ret = ocall_uprint((const char *) buf);
		TEST_CHECK(sgx_ret);
	}
	return res;
}



uint8_t precomputed_seeds[32];


/**
 * Function Name: send_msk
 *
 * Description:
 * Send authority master key
 * @param key: the master key
 * @param keylen: length of master key
 *
 * @return NULL
 */
void send_msk(unsigned char* key, size_t keylen, int signer_id)
{
    uint8_t sk[HASH_SIZE], prior_hash[1000];
    size_t      prior_hash_len = 0, current_counter = 0;

    memcpy(msk, key, keylen);
    msklen = keylen;

    memcpy(prior_hash, msk, msklen);
    memcpy(prior_hash + msklen, (uint8_t*) &signer_id, sizeof(signer_id));
    if (NULL == sha256_i(prior_hash, msklen + sizeof(signer_id), precomputed_seeds, 0))                         { return; }
    

    for (int i = 0 ; i < 999000 ; i++) {
        sha256_i(precomputed_seeds, HASH_SIZE, precomputed_seeds, 2);
    }

    // for (int i = 0 ;  i < 1000; i++) {
    //     sha256_i(precomputed_seeds, HASH_SIZE, precomputed_seeds, 2);
    // }

    // printf("DEBUG [first]:\n");
    // for (int i = 0 ; i < 32 ; i++) {
    //     printf("%lu ", precomputed_seeds[i]);
    // }
    // printf("\n");

}


/**
 * Function Name: request_keys
 *
 * Description:
 * Get the public key (EC point) Yj from the enclave
 * @param encoded_point: EC encoded buffer
 * @param encoded_point_len: length of the EC point encoded buffer
 *
 * @return NULL
 */
void request_keys(uint8_t pk[T * HASH_SIZE], size_t* pk_len,
                  int signer_id, int counter)
{
    uint8_t sk[HASH_SIZE], prior_hash[msklen + sizeof(signer_id)];
    uint8_t seed[HASH_SIZE];
    *pk_len = T * HASH_SIZE;

    memcpy(seed, precomputed_seeds, HASH_SIZE);
    // Compute the current signer's seed using the counter
    for (int i = 0 ;  i < 1000; i++) {
        sha256_i(seed, HASH_SIZE, seed, 2);
    }


    // Compute the current signer's public key
    memcpy(prior_hash, seed, HASH_SIZE);
    for (int i = 0 ; i < T ; i++) {
        memcpy(prior_hash + HASH_SIZE, (uint8_t*) &i, sizeof(i));
        if (NULL == sha256_i(prior_hash, HASH_SIZE + sizeof(i), sk, 1))                            { return; }
        if (NULL == sha256_i(sk, HASH_SIZE, pk + i * HASH_SIZE, 0))                                { return; }
    }
}
