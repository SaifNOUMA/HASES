
#include "Signer.h"
#include <openssl/sha.h>

Signer::Signer(int id)
{
    this->ID        = id;
    this->counter   = 0;
}

Signer::~Signer()
{
}


/**
 * Function Name: setSignerKeys
 *
 * Description:
 * Set the signer's private/public keys
 * @param ec_group: EC group that hold EC domain parameters
 * @param ec_key: The private/public EC keys for the signer.
 *
 * @return 1 on success, 0 on failure
 */
int Signer::setSignerKeys(uint8_t* private_key)
{
    memcpy(this->private_key, private_key, sizeof(this->private_key));
    this->counter = 1000000;

    for (int i = 0 ; i < this->counter ; i++) 
    {
        update_keys();
    }

    return 1;
}

/**
 * Function Name: sign_message
 *
 * Description:
 * Sign the given message using ETA scheme
 * @param message: message to sign
 * @param messagelen: length of the message
 *
 * @return 1 on success, 0 on failure
 */
int Signer::sign_message(uint8_t* message, size_t messagelen,
                         uint8_t** sig, size_t* siglen,
                         size_t* counter)
{   
    int                 count, i, h_subs[K];
    uint8_t         hash[HASH_SIZE];
    uint8_t         *signature = new uint8_t[K * HASH_SIZE];
    uint8_t         prior_hash[HASH_SIZE + sizeof(int)];

    // compute hash = HASH(message)
    if (NULL == sha256_i(message, messagelen, hash, 0))                                       { return 0; }
    
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

    // compute the signature using the corresponsding indices (h_subs)
    memcpy(prior_hash, this->private_key, HASH_SIZE);
    for (i = 0 ; i < K ; i++) {
        memcpy(prior_hash + HASH_SIZE, (uint8_t*) &(h_subs[i]), sizeof(h_subs[i]));
        if (NULL == sha256_i(prior_hash, HASH_SIZE + sizeof(h_subs[i]), signature + i * HASH_SIZE, 1))   { return 0; }
    }
    *sig = signature;
    *siglen = K * HASH_SIZE;

    *counter = this->counter;
    this->counter ++;
    // this->update_keys();
    sha256_i(message, messagelen, hash, 0); // replace update_key

    return 1;
}


/**
 * Function Name: send_signature
 *
 * Description:
 * Send the signature to the verifier (SGX enclave)
 * @param sig: the signature
 * @param siglen: length of the signature
 *
 * @return 1 on success, 0 on failure
 */
int Signer::send_signature(unsigned char* sig, size_t siglen)
{

    return 1;
}

/**
 * Function Name: update_keys
 *
 * Description:
 * Update the signer keys when signing occurs
 * @param sig: the signature
 * @param siglen: length of the signature
 *
 * @return 1 on success, 0 on failure
 */
int Signer::update_keys()
{
    sha256_i(this->private_key, HASH_SIZE, this->private_key, 2);

    return 1;
}
