Red-Black Merkle Tree
=====================

This is a reference implementation of a Self-Balancing Merkle Search Tree (i.e., an Authenticated Data Structure [0]). This can be used to efficiently represent the essential state necessary to validate Bitcoin [1] transactions: the set of available unspent transaction outputs (UTXOs).

Authenticated Data Structures are used in protocols between three parties: 1) the trusted Source, which creates data and publishes a digest; 2) the untrusted Server, which maintains a copy of the data and responds to queries; and 3) the Client, which verifies the Server's responses against the known digest. In this implementation, the data structure requires O(N) storage and each operation takes O(log N) time. These operations can also be verified in worst-case O(log N) time using a Verification Object (a path through a Merkle tree). A verifying Client is only required to maintain O(1) state (specifically, the Merkle tree root hash).

- redblack.py: <code>RedBlack</code> is a general purpose Red-Black binary search tree [3] that can easily be augmented with a 'digest' function. Typically, the digest should include a secure hash function, forming a dynamic Merkle tree [4].

- utxo_merkle.py: a specialization of <code>RedBlack</code> by definining a digest/serialization protocol appropriate for Bitcoin UTXOs.

- merkle_scan.py: a script that iterates through the Bitcoin blockchain, from the genesis block to the head, incrementally updating the <code>RedBlack</code> as it goes (requires Gavin Andresen's <a href="https://github.com/gavinandresen/bitcointools">python bitcointools</a>.

- treedot: produces graphviz illustrations of the tree (requires graphviz (dot))

- test_redblack: unit tests for <code>RedBlack</code>

Illustrations
=============

- Authenticated insertion/balancing in a red-black merkle tree http://imgur.com/a/KNeq5#0

- Teaser Image

<img src="http://i.imgur.com/aFCLo.png" width="400"/>


[0] <a href="http://cs.brown.edu/research/pubs/pdfs/2003/Tamassia-2003-ADS.pdf">Authenticated Data Structures.  Roberto Tamassia. 2003</a><br>
[2] http://bitcoin.org/bitcoin.pdf<br>
[3] http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps<br>
[4] http://cs.brown.edu/people/aris/pubs/pad.pdf<br>

Licensing
=========
This software is released under the CRAPL license (appropriate for scientific use) and the AGPL license (appropriate for copyleft open source projects). If you would like a different or more permissive license, please contact me!
