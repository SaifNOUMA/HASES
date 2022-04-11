#include "util.h"


int encodeBN(BIGNUM* bn, uint8_t** p, size_t* plen)
{
    *plen = BN_num_bytes(bn);
    *p = new uint8_t[*plen];

    BN_bn2bin(bn, *p);

    return 1;
}

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

unsigned long long cpucycles(void)
{
  unsigned long long result;
  __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
    : "=a" (result) ::  "%rdx");
  return result;
}

unsigned long long average(unsigned long long *t, size_t tlen)
{
    unsigned long long acc=0;
    size_t i;
    for(i = 0; i < tlen; i++) {
        acc += t[i];
    }
    return acc/(tlen);
}

void print_results(unsigned long long *t, size_t tlen)
{
  printf("\taverage       : %llu cycles\n", average(t, tlen));
  printf("\n");
}
