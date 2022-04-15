#include "util.h"
#include "conf.h"
#include "App.h"
#include "Enclave_u.h"
#include <ctime>


int verify_signature(size_t enclave_id,
                     uint8_t* sig, size_t siglen,
                     uint8_t* message, size_t messagelen, size_t *request_t,
                     size_t signer_id, size_t counter, int* result, double *req_time)
{
    unsigned char     hash[HASH_SIZE], hash_sig[K * HASH_SIZE], pk[T * HASH_SIZE], publickey[T][HASH_SIZE];
    size_t                  count, i, h_subs[K], a, b, pk_len;
    std::clock_t         t0, t1;
    double                 enclave_computation;


    a = cpucycles();
    t0 = std::clock();
    if (0 != request_keys(enclave_id,
                          pk, &pk_len,
                          signer_id, counter))                                                                                                                    { return 0; }
    t1 = std::clock();
    a = cpucycles() - a;
    *request_t = a;
    enclave_computation = ( (double) (t1 - t0)) / (CLOCKS_PER_SEC / 1000);
    *req_time = enclave_computation;


    // compute hash = HASH(message)
    if (NULL == sha256_i(message, messagelen, hash, 0))                                                                                     { return 0; }
    
    i = 0;
    for (count = 0 ; count < K ; count++) {
        if (count % 2 == 0) {
            h_subs[count] = (hash[i] << 4) | (hash[i+1] >> 4);
            i ++;
        } else {
            h_subs[count] = ((hash[i] << 8) & 0x0F00) | (hash[i+1]);
            i += 2;
        }
    }

    // verify the signature
    *result = 0;
    for (int k = 0 ; k < K ; k++) {
        if (NULL == sha256_i(sig + k * HASH_SIZE, HASH_SIZE, hash_sig + k * HASH_SIZE, 0))            { return 0; }

        *result = memcmp(hash_sig + k * HASH_SIZE, pk + h_subs[k] * HASH_SIZE, HASH_SIZE);
        if (*result != 0)                                                                                                                                           { return 0; }
    }


    return 1;
}
