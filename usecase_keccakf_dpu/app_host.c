/*
 * Copyright 2018 - UPMEM
 * Copyright 2023 - Manjeet Singh Bhatia (UCR)
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)•
 * any later version.
 *
 */

#include "keccakf_dpu_params.h"
#include <dpu.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include <sys/time.h>

#define MAX_LINES 1000
#define MAX_LINE_LENGTH 1000
#define MAX_STR_LEN 17
#define MAX_STR_LEN 1024
#define MAX_NUM_STRS 1024

double dml_micros()
{
    static struct timeval tv;
    gettimeofday(&tv, 0);
    return ((tv.tv_sec * 1000000.0) + tv.tv_usec);
}

void handlefaults(void)
{
    // fault handling will go here, its Simple for now.
    printf("An error occurred\n");
    exit(1);
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

int main(int argc, char **argv)
{
    const uint64_t fkey = argc > 1 ? atoi(argv[1]) : 0; /* first key */
    const uint64_t lkey = argc > 2 ? atoi(argv[2]) : 1 << 10; /* last  key */
    const uint64_t loops = argc > 3 ? atoi(argv[3]) : 1 << 20; /* #loops    */
    const uint64_t nkey = lkey - fkey;
    struct dpu_set_t dpus;
    struct dpu_set_t dpu;
    struct dpu_program_t *dpu_program;
    uint32_t nr_of_dpus, nr_of_tasklets;
    unsigned int t, i, idx;
    int res = -1;
    
    // private/public key pair for sign and verify
    EVP_PKEY *pkey;
    pkey = EVP_PKEY_new();
    RSA *rsa;
    rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);
    

    DPU_ASSERT(dpu_alloc(DPU_ALLOCATE_ALL, NULL, &dpus));
    DPU_ASSERT(dpu_load(dpus, DPU_BINARY, &dpu_program));

    DPU_ASSERT(dpu_get_nr_dpus(dpus, &nr_of_dpus));
    nr_of_tasklets = nr_of_dpus * NR_TASKLETS;
    printf("Allocated %d DPU(s) x %d Threads\n", nr_of_dpus, NR_TASKLETS);

    /* send parameters to the DPU tasklets */
    idx = 0;
    DPU_FOREACH (dpus, dpu) {
        struct dpu_symbol_t tasklet_params;
        DPU_ASSERT(dpu_get_symbol(dpu_program, "tasklet_params", &tasklet_params));
        struct dpu_params params;
        params.loops = loops;
        for (t = 0; t < NR_TASKLETS; t++, idx++) {
            params.fkey = fkey + (nkey * idx + nr_of_tasklets - 1) / nr_of_tasklets;
            params.lkey = fkey + (nkey * (idx + 1) + nr_of_tasklets - 1) / nr_of_tasklets;
            if (params.lkey > lkey)
                params.lkey = lkey;
            //printf(" Thread %02d-%02d %d->%d\n", idx / NR_TASKLETS, t, params.fkey, params.lkey);
            DPU_ASSERT(dpu_copy_to_symbol(dpu, tasklet_params, t * sizeof(params), (const uint8_t *)&params, sizeof(params)));
        }
    }

    printf("Run program on DPU(s)\n");
    double micros = dml_micros();
    DPU_ASSERT(dpu_launch(dpus, DPU_SYNCHRONOUS));
    micros -= dml_micros();

    printf("Retrieve results\n");
    struct dpu_result *results;
    unsigned long long sum = 0;
    uint64_t cycles = 0;
    results = calloc(sizeof(results[0]), nr_of_dpus);
    if (!results)
        goto err;
    i = 0;
    //size_t n = 0;
    FILE* stdout_orig = stdout;
    FILE* file = freopen("output.txt", "a", stdout);
    DPU_FOREACH (dpus, dpu) {
        /* Retrieve tasklet results and compute the final keccak. */
        struct dpu_symbol_t tasklet_results;
        DPU_ASSERT(dpu_get_symbol(dpu_program, "tasklet_results", &tasklet_results));
        for (t = 0; t < NR_TASKLETS; t++) {
            struct dpu_result tasklet_result = { 0 };
            DPU_ASSERT(dpu_copy_from_symbol(
                dpu, tasklet_results, t * sizeof(tasklet_result), (uint8_t *)&tasklet_result, sizeof(tasklet_result)));
            results[i].sum ^= tasklet_result.sum;
            //printf("hash is %ld \n", tasklet_result.sum);
            if (tasklet_result.cycles > results[i].cycles)
                results[i].cycles = tasklet_result.cycles;
        }
        DPU_ASSERT(dpu_log_read(dpu, stdout));
		stdout = stdout_orig;
        sum ^= results[i].sum;
        if (results[i].cycles > cycles)
            cycles = results[i].cycles;
        i++;
    }
    //for (i = 0; i < nr_of_dpus; i++)
      //  printf("DPU cycle count = %" PRIu64 " cc\n", results[i].cycles);
    fclose(file);
    if(freopen("/dev/tty", "a", stdout)==NULL){
        handlefaults();
    }
    char filename[] = "output.txt";
    char str[MAX_STR_LEN];
    //char* str_array[MAX_NUM_STRS];
    int num_strs = 0;
    // Generate a key pair for sign and verify
    
     
    FILE* file2 = fopen(filename, "r");
    if (file2 == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    
    while (fgets(str, MAX_STR_LEN, file2) != NULL) {
        if (strncmp(str, "===", 3) != 0) {  // if string doesn't start with "==="
            //printf("%s", str);
            unsigned char *sig;
            size_t sig_len;
            if (!sign(str, 18, pkey, &sig, &sig_len)) {
                handlefaults();
            }        
     
            int verified;
            verified = verify(str, 18, sig, sig_len, pkey);
            num_strs++;
        }
    }
    
    fclose(file2);
    
    // Print the hexadecimal strings
    double secs = -micros / 1000000.0;
    double Mks = loops * (lkey - fkey) / 1000000.0 / secs;
    printf("_F_ fkey= %6u lkey= %6u loops= %6d SUM= %llx seconds= %1.6lf   Mks= %1.6lf\n", (unsigned int)fkey, (unsigned int)lkey,
        (unsigned int)loops, sum, secs, Mks);

    double dpu_secs = cycles / 600000000.0;
    double dpu_Mks = loops * (lkey - fkey) / 1000000.0 / dpu_secs / nr_of_dpus;
    printf("DPU fkey= %6u lkey= %6u loops= %6d SUM= %llx seconds= %1.6lf   Mks= %1.6lf\n", (unsigned int)fkey, (unsigned int)lkey,
        (unsigned int)loops, sum, dpu_secs, dpu_Mks);

    free(results);
    res = 0;

err:
    DPU_ASSERT(dpu_free(dpus));
    return res;
}
