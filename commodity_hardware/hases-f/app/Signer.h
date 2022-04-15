
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "util.h"
#include "conf.h"

class Signer
{
private:
    int             counter;
    uint8_t         private_key[SEED_SIZE];


public:
    Signer(int id);
    ~Signer();

    int setSignerKeys(uint8_t* private_key);

    int sign_message(uint8_t* message, size_t messagelen,
                     uint8_t** sig, size_t* siglen,
                     size_t* counter);

    int send_signature(unsigned char* sig, size_t siglen);

    int update_keys();

    int             ID;
};
