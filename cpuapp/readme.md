Crypto wallet identity verification
===================================

Crypto wallets or digital crypto uses many ways to secure and verify user identity, one
such way is to compute unique hashes of user identity, sign it using user's public key
and then verify before giving acess.


How to Run
----------
1. Edit the Num of threads and input size in verify_hash.c by changing below lines

    #define MAX_SIZE 200000

    #define OMP_THREADS 64

2. make

3. make run
