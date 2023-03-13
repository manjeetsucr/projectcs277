Keccakf implementation of UPMEM DPU
===================================
This application offloads the computation of keccakf-sha256 hashes to in memory compute,
and does signing and verifying on the cpu after getting computed hashes from DPUs.

Crypto wallets or digital crypto uses many ways to secure and verify user identity, one
such way is to compute unique hashes of user identity, sign it using user's public key
and then verify before giving acess.


How to Run
----------

make
make run


How the algorithm run on DPUs
-----------------------------

The keccakf algorithm consists on running the keccakf function several times (defined by the third argument ``loops``) on each key between the first and last key (defined by the first and second argument).

The DPU implementation takes all the keys that need to be computed, and divides them equally on each DPU. Then each DPU runs the keccakf function as many time as defined by the ``loops`` argument on each key it has been assigned.

Performances
------------

