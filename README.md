Red-Black Merkle Tree Sampler
=============================

An authenticated dictionary that provides the following operations:

    getRandomElement()
    query()
    insert()
    delete() # not implemented yet

Each of these operations takes O(log N) time and requires O(N) storage. These operations also produce an O(log N) Verification Object (a path through a Merkle tree) that can be used by a client to verify the operation with O(log N) effort. The client is only required to maintain O(1) state, specifically the Merkle tree root hash.

The intended application of this is to provide public proofs-of-throughput (random access) to an authenticated datastructure, e.g., the Bitcoin 'unspent coins' database.

The implementation uses a Red-Black tree [1] adapted to form a Merkle hash tree [2]. Selection of random elements (uniformly) is provided by maintaining a separate array containing the elements [3]. Each array index is stored along with the value in the tree.

[1] http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps
[2] http://cs.brown.edu/people/aris/pubs/pad.pdf
[3] http://stackoverflow.com/questions/5682218/data-structure-insert-remove-contains-get-random-element-all-at-o1

Illustrations
=============
http://imgur.com/a/KNeq5#0