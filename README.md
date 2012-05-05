Red-Black Merkle Tree Sampler
=============================

This is a demonstration of an Authenticated Data Structure [0] that provides the following operations:

    query()       # test an element for set membership
    delete()      # not implemented yet
    insert()
    select()      # Select an element from the set using an index 0..N

Authenticated Data Structures are used in protocols between three parties: 1) the trusted Source, which creates the data and publishes a digest; 2) the untrusted Server, which maintains a copy of the data and responds to queries; and 3) the Client, which verifies the Server's responses against the known digest.

In this implementation, the data structure requires O(N) storage and each operation takes O(log N) time. These operations can also be verified in worst-case O(log N) time using a Verification Object (a path through a Merkle tree). A verifying Client is only required to maintain O(1) state (specifically, the Merkle tree root hash).

This datastructure can be used to make a proof-of-throughput, by which a Server proves that it can respond to some number of queries per second. A cloud-storage provider could use this to make claims about the redundancy of its storage layout, using an approach similar to [1]. The Client selects a random value <code>p</code> and issues it to the Server as a challenge. The Server responds by finding a solution <code>q</code> such that when <code>p||q</code> is used as the seed to a PRF, and a random walk is taken through <code>k</code> elements in the set (adding to a Hash-based accumulator along the way), the final accumulator value falls below a difficulty threshold. This is similar to the proof-of-work scheme in Bitcoin [2]. In fact, the motivation for this data structure is to replace the current proof-of-work scheme in Bitcoin with an alternate one based on proof-of-availability to the 'unspent coins' database.

This implementation consists of  augmented with a secure hash function to form a dynamic Merkle tree. The tree is also augmented with a 'size' field, in order to select random elements uniformly from the set in O(log N) time.

- redblack.py: <code>RedBlackTree</code> is a general purpose Red-Black binary search tree [3] that can easily be augmented with a 'digest' function. <code>AuthSelectRedBlackTree</code> augments this structure with a secure hash function, forming a dynamic Merkle tree. It also includes a 'size' field so that elements can be selected uniformly randomly.

- proofofwork.py: uses the <code>AuthSelectRedBlack</code> to produce proofs-of-throughput to the select() function


Illustrations
=============

- Authenticated insertion/balancing in a red-black merkle tree http://imgur.com/a/KNeq5#0

- Teaser Image

<img src="http://i.imgur.com/aFCLo.png" width="400"/>


[0] <a href="http://cs.brown.edu/research/pubs/pdfs/2003/Tamassia-2003-ADS.pdf">Authenticated Data Structures.  Roberto Tamassia. 2003</a><br>
[1] <a href="http://www.rsa.com/rsalabs/staff/bios/kbowers/publications/RAFT.pdf">How to Tell if Your Cloud Files are Vulnerable to Drive Crashes. Bowers, Dijk, Juels, Oprea, and Rivest. 2011</a><br>
[2] http://bitcoin.org/bitcoin.pdf<br>
[3] http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps<br>
[4] http://cs.brown.edu/people/aris/pubs/pad.pdf<br>
[5] http://stackoverflow.com/questions/5682218/data-structure-insert-remove-contains-get-random-element-all-at-o1<br>
