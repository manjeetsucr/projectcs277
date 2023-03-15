Keccakf Hash implementation of UPMEM DPU and Sign, Verify on CPU
================================================================

This application offloads the computation of keccakf-sha256 hashes to in memory compute,
and does signing and verifying on the cpu after getting computed hashes from DPUs.

Crypto wallets or digital crypto uses many ways to secure and verify user identity, one
such way is to compute unique hashes of user identity, sign it using user's public key
and then verify before giving acess.


How to Run
----------
1. Edit the number of keys to generate hashes in line 37 of MakeFile

   @$(shell readlink -f $(HOST_EXE)) 0 200000 1 > ${OUTPUT_FILE} will have input size of 200000

2. Change Number of CPU threads in app_host.c

    #define OMP_THREADS 128  

3. make

4. make run
