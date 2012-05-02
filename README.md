Red-Black Merkle Tree Sampler
=============================

A demonstration of an Authenticated Datastructure [0] that provides the following operations:

    getRandomElement()
    query()
    insert()
    delete() # not implemented yet

In this implementation, each of these operations takes O(log N) time and requires O(N) storage. These operations also produce an O(log N) Verification Object (a path through a Merkle tree) that can be used by a client to verify the operation with O(log N) effort. The client is also only required to maintain O(1) state (specifically, the Merkle tree root hash).

The application of this datastructure is to provide proofs-of-availability, that is, a measure of random access throughput for queries to the data. This could be used by a Cloud Storage provider to make claims about the fault tolerance of its storage layout, as in [1]: The Client issues an O(1) challenge consisting of a random string. The Server responds to the challenge <code>p</code> by trying to find a solution <code>q</code> such that using <code>q|p</code> as the seed to a PRF, a random sequential walk through k of stored elements (accumulating a hash along the way) produces a result below a threshold (similar to the proof-of-work in Bitcoin [2]).

The implementation of this datastructure consists of a) an array, and b) a Red-Black binary search tree [3] containing Merkle hashes [4]. There is a one-to-one mapping between elements in the array and leaves in the tree [5], so that uniform selection of random elements can be performed by selecting a random array index from <code>0..N-1</code> and searching for this value in the tree.

[0] http://cs.brown.edu/research/pubs/pdfs/2003/Tamassia-2003-ADS.pdf
[1] http://www.rsa.com/rsalabs/staff/bios/kbowers/publications/RAFT.pdf<br>
[2] http://bitcoin.org/bitcoin.pdf<br>
[3] http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps<br>
[4] http://cs.brown.edu/people/aris/pubs/pad.pdf<br>
[5] http://stackoverflow.com/questions/5682218/data-structure-insert-remove-contains-get-random-element-all-at-o1<br>

Illustrations
=============

- Authenticated insertion/balancing (album) http://imgur.com/a/KNeq5#0

- Teaser Image

<img src="http://i.imgur.com/aFCLo.png" width="400"/>