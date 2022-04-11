

#include <Crypto.h>
#include <BLAKE2s.h>
#include <bitHelpers.h>
#include <string.h>
#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif

#define HASH_SIZE 32
#define BLOCK_SIZE 64
#define N 10
#define T 11966
#define K 13

BLAKE2s blake2s;
uint8_t private_key[HASH_SIZE];


int sign_message(Hash *hash,
                 uint8_t* message, size_t messagelen,
                 uint8_t* sig, int *siglen)
{
  int       i, h_subs[K], count = 0;
  uint8_t   *signature = new uint8_t[K * HASH_SIZE];
  uint8_t   prior_hash[HASH_SIZE + sizeof(int)];
  uint16_t  subs[K];


  // compute hash = HASH(message)
  hash->reset();
  hash->update(message, sizeof(message));
  hash->finalize(prior_hash, sizeof(prior_hash));


  i = 0;
  memset(subs, 0, sizeof(subs));
  for (count = 0 ; count < K ; count ++) {
    if (count %2 == 0) {
      subs[count] = (prior_hash[i] << 4) | (prior_hash[i+1] >> 4);
      i ++;
    } else {
      subs[count] = ((prior_hash[i] << 8) & 0x0F00) | (prior_hash[i+1]);
      i += 2;
    }

  }

  // compute the signature using the corresponsding indices (h_subs)
  memcpy(prior_hash, private_key, sizeof(private_key));

  for (i = 0 ; i < K ; i++) {
    memcpy(prior_hash + HASH_SIZE, (uint8_t*) &(h_subs[i]), sizeof(h_subs[i]));
    
    hash->reset();
    hash->update(prior_hash, HASH_SIZE + sizeof(uint16_t));
    hash->finalize(signature + i * HASH_SIZE, HASH_SIZE);
  }

  // update the private key
  hash->reset();
  hash->update(private_key, HASH_SIZE);
  hash->finalize(private_key, HASH_SIZE);

  memcpy(sig, signature, HASH_SIZE);
}


void setup()
{
  int     retval, count;
  int     siglen;
  unsigned long long  elapsed, start;
  uint8_t message[32], sig[HASH_SIZE];


  Serial.begin(9600);
  memset(message, 0, 32);
  memset(private_key, 0, sizeof(private_key));

  Serial.println("Hashing ...");
  
  elapsed = 0;
  for (count = 0 ; count < N ; count++) {
    start = micros();
    retval = sign_message(&blake2s,
                          message, sizeof(message),
                          sig, &siglen);
    elapsed += micros() - start;
  }

  Serial.print(elapsed / (double) N);
  Serial.println("us");
}

void loop() {}
