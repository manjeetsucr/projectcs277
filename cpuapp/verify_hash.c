#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <omp.h>

#define MAX_SIZE 200000
#define OMP_THREADS 64

void handlefaults(void)
{
    // fault handling will go here, its Simple for now.
    printf("An error occurred\n");
    exit(1);
}


// Generate hash of an integer message
int generate_hash(int *message, size_t message_len, unsigned char *hash_res){

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    md = EVP_sha256();
    int md_len;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message, message_len);
    EVP_DigestFinal_ex(mdctx, hash_res, &md_len);
    EVP_MD_CTX_free(mdctx);
    return md_len;

}

// sign the hash and store it in md_value.
int sign(unsigned char *md_value, unsigned int md_len, EVP_PKEY *pkey, unsigned char **sig, size_t *sig_len)
{
    EVP_MD_CTX *mdctx_sign;
    mdctx_sign = EVP_MD_CTX_new();
    const EVP_MD *md;
    md = EVP_sha256();
    EVP_SignInit(mdctx_sign, md);
    EVP_SignUpdate(mdctx_sign, md_value, md_len);
    *sig = malloc(EVP_PKEY_size(pkey));
    if (!EVP_SignFinal(mdctx_sign, *sig, sig_len, pkey)) {
        handlefaults();
    }
    EVP_MD_CTX_free(mdctx_sign);

    return 1;
}


// verfiy the hash with signature
int verify(unsigned char *md_value, unsigned int md_len, unsigned char *sig, size_t sig_len, EVP_PKEY *pkey)
{

    EVP_MD_CTX *mdctx_verify;
    mdctx_verify = EVP_MD_CTX_new();
    const EVP_MD *md;
    md = EVP_sha256();
    EVP_VerifyInit(mdctx_verify, md);
    EVP_VerifyUpdate(mdctx_verify, md_value, md_len);
    int verified;
    verified = EVP_VerifyFinal(mdctx_verify, sig, sig_len, pkey);
    EVP_MD_CTX_free(mdctx_verify);

    return verified;
}



int main(void)
{
    OpenSSL_add_all_algorithms();


    // Generate a key pair for sign and verify
    EVP_PKEY *pkey;
    pkey = EVP_PKEY_new();
    RSA *rsa;
    rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);
    

    int message =0;
    double start, end;

    omp_set_num_threads(OMP_THREADS);

    start = omp_get_wtime();
    
    #pragma omp parallel private(message)
    #pragma omp for
    for (message=0; message<MAX_SIZE; message++){
    unsigned char *msg_bytes = (unsigned char *)&message;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    unsigned char *sig;
    size_t sig_len;
    size_t message_len = sizeof(int);


    md_len = generate_hash((int *)msg_bytes, message_len, md_value);
    if (!sign(md_value, md_len, pkey, &sig, &sig_len)) {
        handlefaults();
    } 
     
    int verified;
    verified = verify(md_value, md_len, sig, sig_len, pkey);

    // Print the verification result
    if (verified == 1) {
        printf("Verification successful \n");
    } else if (verified == 0) {
        printf("Verification failed \n");
    } else {
        handlefaults();
    }

    free(sig);
}

    // Clean up and free memory
    end = omp_get_wtime();
    EVP_PKEY_free(pkey);
    EVP_cleanup();
    printf("Time taken is for generating hashes and signing %f seconds\n", end-start);

    return 0;
}

