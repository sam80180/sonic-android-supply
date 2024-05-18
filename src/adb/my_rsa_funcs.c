#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>
#include "my_rsa_funcs.h"

char last_error_string[2048] = {0};

int rsa_public_verify(unsigned char *m, unsigned char *sigbuf, unsigned char* strPEMPubKey) {
    BIO *bio = BIO_new_mem_buf(strPEMPubKey, strlen(strPEMPubKey));
    RSA *public_key = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    int n = RSA_verify(NID_sha1, m, strlen(m), sigbuf, strlen(sigbuf), public_key);
    if (n==-1) {
        snprintf(last_error_string, sizeof(last_error_string), "%s", ERR_error_string(ERR_get_error(), NULL));
    } // end if
    RSA_free(public_key);
    return n;
} // end rsa_public_verify()

/*
References:
https://www.openssl.org/docs/man3.0/man3/RSA_verify.html
https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/daemon/auth.cpp#177
*/
