Red-Black Merkle Tree
=====================

This is a demonstration of an Authenticated Data Structure [0] that can be used to provide proofs-of-throughput, by which a Server demonstrates that it is capable of responding to some minimum number of queries within a time interval.

A cloud-storage provider could use this to make public claims about the redundancy of its storage layout, using an approach similar to [1]. Bitcoin [2] miners could use this to demonstrate their access to the 'unspent coins' database, which is necessary to validate transactions.

Authenticated Data Structures are used in protocols between three parties: 1) the trusted Source, which creates data and publishes a digest; 2) the untrusted Server, which maintains a copy of the data and responds to queries; and 3) the Client, which verifies the Server's responses against the known digest. In this implementation, the data structure requires O(N) storage and each operation takes O(log N) time. These operations can also be verified in worst-case O(log N) time using a Verification Object (a path through a Merkle tree). A verifying Client is only required to maintain O(1) state (specifically, the Merkle tree root hash).

A Server can prove it can service some throughput of queries to this data structure per second. The Client selects a random value <code>p</code> and issues it to the Server as a challenge. The Server responds by finding a solution <code>q</code> such that when <code>p||q</code> is used as the seed to a PRF, and a random walk is taken through <code>k</code> elements in the set (adding to a Hash-based accumulator along the way), the final accumulator value falls below a difficulty threshold. This is similar to the proof-of-work scheme in Bitcoin [2]. In fact, the motivation for this data structure is to replace the current Bitcoin proof-of-work with an alternative one based on a proof-of-efficiency for queries to 'unspent coins' database.

- redblack.py: <code>RedBlack</code> is a general purpose Red-Black binary search tree [3] that can easily be augmented with a 'digest' function. At minimum, the tree is augmented with a 'size' field so that verification can be constrained to take O(log N) time. Typically, the digest should include a secure hash function, forming a dynamic Merkle tree [4].

- proofofthroughput.py: a general construction of proofs-of-throughput. Several examples are given, especially one using the select() function of an <code>RedBlack</code>.

- toycoin.py: a simple version of Bitcoin based on storing the 'unspent coins' in an <code>RedBlack</code>


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
