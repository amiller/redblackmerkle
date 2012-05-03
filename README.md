Red-Black Merkle Tree Sampler
=============================

This is a demonstration of an Authenticated Data Structure* [0] that provides the following operations:

    get_random()      # Select an element from the set at random (uniformly)
    query()           
    insert()          
    delete()          # not implemented yet

Authenticated Data Structures are typically used in protocols between three parties: 1) the trusted Source, which creates the data and publishes a digest; 2) the untrusted Server, which maintains a copy of the data and responds to queries; and 3) the Client, which queries the server and verifies the responses against the known digest.

In this implementation, the data structure requires O(N) storage and each operation takes O(log N) time. These operations also each produce an O(log N) Verification Object (a path through a Merkle tree) that can be used by a Client to verify the operation with O(log N) effort. The Client is only required to maintain O(1) state (specifically, the Merkle tree root hash).

This datastructure can be used to make a proof-of-availability, by which the Server proves that it can respond to at least some number of accesses per second. A cloud-storage provider could use this to make claims about the redundancy of its storage layout, as described in [1]: the Client selects a random string <code>p</code> and issues it to the Server as a challenge. The Server responds by finding a solution <code>q</code> such that when <code>p || q</code> as the seed to a PRF and a random walk is taken through <code>k</code> elements in the set (adding to a Hash-based accumulator along the way), the final accumulator value falls below a difficulty threshold. This is similar to the proof-of-work scheme in Bitcoin [2].

This implementation consists of a) an array, and b) a Red-Black binary search tree [3] containing Merkle hashes [4]. There is a one-to-one mapping between elements in the array and leaves in the tree [5], so that uniform selection of random elements can be performed in O(log N) time by selecting an array index from <code>0..N-1</code> and searching for the corresponding value in the tree.


- authredblack.py: <code>AuthRedBlackTree</code> is an Authenticated Set based on a Red-Black tree, supporting query(), insert(), and delete()

- sampler.py: <code>MerkleSampler</code> additionally supports get_random() by combines the <code>AuthRedBlackTree</code> with an array

- proofofwork.py: uses the MerkleSampler


Illustrations
=============

- Authenticated insertion/balancing in a red-black merkle tree http://imgur.com/a/KNeq5#0

- Teaser Image

<img src="http://i.imgur.com/aFCLo.png" width="400"/>


[0] http://cs.brown.edu/research/pubs/pdfs/2003/Tamassia-2003-ADS.pdf<br>
[1] http://www.rsa.com/rsalabs/staff/bios/kbowers/publications/RAFT.pdf<br>
[2] http://bitcoin.org/bitcoin.pdf<br>
[3] http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps<br>
[4] http://cs.brown.edu/people/aris/pubs/pad.pdf<br>
[5] http://stackoverflow.com/questions/5682218/data-structure-insert-remove-contains-get-random-element-all-at-o1<br>
