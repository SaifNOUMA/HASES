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


#include "App.h"
#include "conf.h"
#include "Authority.h"
#include "verify.cpp"
#include "Enclave_u.h"

#define J 10000

using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t    global_eid = 0;


/* OCall functions */
void ocall_uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    fflush(stdout);
}


/* Application entry */
int main()
{
    Authority*      authority;
    Signer*         signer = NULL;
    uint8_t         *message, *sig;
    size_t          messagelen, counter, siglen;
    int             result, status;
    unsigned long long sign_t[J], ver_t[J], request_pk_t;
    double average_req = 0.0, req_t;
    

    authority = new Authority();
    authority->init();
    authority->init_parties(&global_eid, &signer);

    for (int i = 0 ; i < J ; i++) {

        messagelen  = 32;
        message     = new uint8_t[messagelen];
        if (0 == RAND_bytes(message, messagelen)) {
            cout << "Error in message generation" << endl;
        }

        
        sign_t[i]  = cpucycles();
        status = signer->sign_message(message, messagelen,
                                    &sig, &siglen, &counter);
        sign_t[i] = cpucycles() - sign_t[i];
        // if (status == 1) {
        //     cout << "Signer:   Message was signed successfully." << endl;
        // } else {
        //     cout << "Signer:   Message signing failed." << endl;
        // }


        ver_t[i] = cpucycles();
        status = verify_signature(global_eid, sig, siglen, message, messagelen, &request_pk_t,
                                signer->ID, counter, &result, &req_t);
        ver_t[i] = cpucycles() - ver_t[i] - request_pk_t;
        average_req += req_t;
        // if (result == 0) {
        //     cout << "Verifier: Signature was accepted." << endl;
        // } else {
        //     cout << "Verifier: Signature was denied." << endl;
        // }
    }

    print_results(sign_t, J);
    print_results(ver_t, J);


    return 0;
}
