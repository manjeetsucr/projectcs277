Keccakf implementation of UPMEM DPU
===================================

How to Run
----------

``
make
make run
make check
``

How the algorithm run on DPUs
-----------------------------

The keccakf algorithm consists on running the keccakf function several times (defined by the third argument ``loops``) on each key between the first and last key (defined by the first and second argument).

The DPU implementation takes all the keys that need to be computed, and divides them equally on each DPU. Then each DPU runs the keccakf function as many time as defined by the ``loops`` argument on each key it has been assigned.

Performances
------------

A single DPU computes ``0.0474 Mks``.

For a typical configuration of 2048 DPUs, the overral performance is ``97 Mks``.
