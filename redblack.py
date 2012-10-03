
"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012

This RedBlack tree is an Authenticated Set [1], based on a balanced
binary search tree. The tree is strictly balanced, so that all usual
operations can be performed in O(log N) worst-case time. The tree is augmented
with secure hashes for each node, forming a Merkle tree. This allows each 
operation to be 'replayed' by a Verifier using only O(log N) data. Only O(1) of
'trusted' state (the Merkle tree root hash) must be maintained by the Verifier.

Additionally, this tree supports selection of an element by its rank, which is
especially useful in choosing elements at random for a Proof-of-Throughput.

This implementation uses a combination of Okasaki style balancing for 
insert [2] and Kazu Yamamato's version of delete [3,4,5].


[1] Persistent Authenticated Dictionaries and Their Applications
    Agnostopolous, Goodrich, and Tamassia.
    http://cs.brown.edu/people/aris/pubs/pad.pdf

[2] Purely Functional Data Structures
    Chris Okasaki
    http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps

[3] Missing method: How to delete from Okasaki's red-black trees
    Matt Might
    http://matt.might.net/articles/red-black-delete/

[4] Efficient Verified Red-Black Trees
    Andrew Appel
    http://www.cs.princeton.edu/~appel/papers/redblack.pdf

[5] Purely Functional Left-Leaning Red-Black Trees
    Kazu Yamamoto
    http://www.mew.org/~kazu/proj/red-black-tree/


Type definitions and common notations:
======================================

RedBlack():
    A RedBlack tree that can be augmented with a 'digest' field, which is
    assumed to contain at least a collision-resistant hash function. The
    digests for the subtrees are stored along with each node. The digests
    are recomputed as necessary during insert and delete in order to maintain
    consistency.

 ** Note that RedBlack objects simply define functions, the actual data 
    structure D is just a tuple, as described below

D:
    A Node in the tree, especially the root. Of the form:
        (Color, Left, (Element, LeftDigest, RightDigest), Right) = D

    - Typically abbreviated
        (c, L, (k, dL, dR), R) = D

    - c in ('R', 'B'): red and black labels for balancing
        L, R: the children, also Nodes,
        dL, dR: digests of the children
        k: each non-leaf's value is equal to the largest leaf value in the left
           sub-tree

    - () represents the empty tree.
    - dO == digest(()) is the empty-digest

    - The following operations are defined as you'd expect:

        D = insert(q, D)   # unless q is already in the set
        D = delete(q, D)   # unless the set does not contain q
        v = search(q, D)   # Returns the smallest element >= q, unless q is the
                           # largest element in the tree

VO:
    Each of the tree operations is defined in terms of a stateful 'Traversal'
    object, which runs in one of two modes:

    Record: 
        The data for every node visited during subsequent operations on T
        is appended to a Verification Object (VO).

        T = record(D)
        d0 = T.insert(q)
        VO = T.VO

    Replay: 
        A VO created from a recording can be replayed, simulating the
        operation on the full tree.

        T = replay(d0, VO)
        d0 = T.insert(q)

 ** Security Claim **

    If an operation on a Replay traversal returns a value, then it is the same
    value that would be returned by the operation on the original tree.

    Proof sketch:
       At each step during a traversal, the digest for each node is known
       before the node's data is accessed. During a Replay, the digest is
       is recomputed and verified.

 ** Bounded Cost-of-Verification Claim **

    The tree is balanced such that the longest possible path from the root to
    a leaf is 2 log N. The worst-case bounds for all operations are given
    below:
          delete: 4 + 3 log N
          insert: 2 log N
          search: 2 log N

    TODO: I think these are wrong! How to construct the worst case?
"""

class DuplicateElementError(ValueError):
    pass

from itertools import izip

class RedBlack(object):
    def __init__(self, E=()):
        """
        Args:
            E: the empty tree
        """
        self.E = E
        # TODO: each of the balance operations sometimes produces more 
        # 'proof' than is necessary. For example, if bL2 is a match,
        # then a 'negative proof' for bL1 is unnecessary. Is there a way
        # to resolve this using the same coroutine setup I have?
        R,B,a,b,c,d,x,y,z = 'RBabcdxyz'
        self.bL1 = (B,(R,(R,a,x,b),y,c),z,d), (R,(B,a,x,b),y,(B,c,z,d))
        self.bL2 = (B,(R,a,x,(R,b,y,c)),z,d), (R,(B,a,x,b),y,(B,c,z,d))
        self.bR1 = (B,a,x,(R,(R,b,y,c),z,d)), (R,(B,a,x,b),y,(B,c,z,d))
        self.bR2 = (B,a,x,(R,b,y,(R,c,z,d))), (R,(B,a,x,b),y,(B,c,z,d))

    """ 
    These are the default "context" functions. They simply pass through
    the node type as the digest type
    """
    def empty(self, D):
        return D == self.E

    def store(self, c, L, k, R):
        return (c, L, k, R)
                                   
    def get(self, D):
        return D


    """
    These are the balancing routines, defined as actions in this context
    """
    def balanceL(self, c, L, k, R):
        D = self.store(c, L, k, R)
        return self.match(self.bL1, D) or self.match(self.bL2, D) or D

    def balanceR(self, c, L, k, R):
        D = self.store(c, L, k, R)
        return self.match(self.bR1, D) or self.match(self.bR2, D) or D

    def unbalancedL(self, c, L, k, R):
        store = self.store
        balanceL = self.balanceL
        red = lambda (_,L,x,R): ('R',L,x,R)
        (_c, _L, _k, _R) = self.get(L)
        if _c == 'B': return balanceL('B',store('R',_L,_k,_R),k,R), c=='B'
        _R = self.get(_R)
        assert c == 'B' and _c == 'R' and _R[0] == 'B'
        return store('B',_L,_k,balanceL('B',store(*red(_R)),k,R)), False

    def unbalancedR(self, c, L, k, R):
        store = self.store
        balanceR = self.balanceR
        red = lambda (_,L,x,R): ('R',L,x,R)
        (_c, _L, _k, _R) = self.get(R)
        if _c == 'B': return balanceR('B',L,k,store('R',_L,_k,_R)), c=='B'
        _L = self.get(_L)
        assert c == 'B' and _c == 'R' and _L[0] == 'B'
        return store('B',balanceR('B',L,k,store(*red(_L))),_k,_R), False

    def match(self, (lhs, rhs), value):
        # Simulates Haskell pattern matching so we can copy the Okasaki
        # balancing rules directly
        table = {}
        get = self.get
        store = self.store

        def _match(left, value):
            if left in ('R','B'): return left == value
            if isinstance(left, tuple):
                return not self.empty(value) and all((_match(*pair) for pair in
                                            izip(left, get(value))))
            table[left] = value
            return True

        def _constr(right, value):
            if right in ('R','B'): return right
            if isinstance(right, tuple):
                return store(*(_constr(*pair) for pair in
                               izip(right, get(value))))
            return table[right]

        return _constr(rhs, value) if _match(lhs, value) else None



    """
    Search, Insert, Delete
    """
    
    def search(self, q, D):
        while True:            
            c, L, k, R = self.get(D)
            if self.empty(L) and self.empty(R): return k
            D = L if q <= k[0] else R

    def insert(self, q, D, v=''):
        balanceL = self.balanceL
        balanceR = self.balanceR
        store = self.store
        get = self.get
        E = self.E
        empty = self.empty

        leaf = store('B', E, (q,v), E)
        if empty(D): return leaf

        def ins(D):
            (c, L, k, R) = get(D)
            node = ('B', L, k, R)
            kk, _ = k

            if q == kk:
                raise DuplicateElementError("Can't insert duplicate element")

            if q < kk and empty(L): return store('R', leaf,  (q,()), store(*node))
            if q > kk and empty(R): return store('R', store(*node), (kk,()), leaf)

            if q < kk: return balanceL(c, ins(L), (kk,()), R)
            if q > kk: return balanceR(c, L, (kk,()), ins(R))
        
        blacken = lambda (_,L,k,R): ('B',L,k,R)
        return store(*blacken(get(ins(D))))


    def delete(self, q, D):
        unbalancedL = self.unbalancedL
        unbalancedR = self.unbalancedR
        store = self.store
        get = self.get
        empty = self.empty
        E = self.E

        def _del(D):
            """
            This function recursively 'bubbles' up three values
            First, the digest of the subtree after deleting the element
            Second, a flag indicating whether we're unbalanced by one
            Third, the maximum value in the subtree, in case the previous 
                   maximum was the deleted element
            """
            if empty(D): return self.E, False, None
            c, L, k, R = get(D)
            if empty(L) and empty(R):
                assert q == k[0]
                return E, True, None
            if q <= k[0]:
                _L, d, m = _del(L)
                if empty(_L): return R, c=='B', None
                if q == k[0]:
                    assert m is not None
                    k = (m,())
                t = (c, _L, k, R)
                if d: return unbalancedR(*t) + (None,)
                else: return store(*t), False, None
            if q  > k[0]:
                _R, d, m = _del(R)
                if empty(_R): return L, c=='B', k[0]
                t = (c, L, k, _R)
                if d: return unbalancedL(*t) + (m,)
                else: return store(*t), False, m

        blacken = lambda (_,L,x,R): ('B',L,x,R)
        d, _, _ = _del(D)
        return E if empty(d) else store(*blacken(get(d)))


    def preorder_traversal(self, d0):
        def _recons(d0):
            if d0 == self.E: return
            (c, dL, k, dR) = self.get(d0)
            yield c, k
            for L in _recons(dL): yield L
            for R in _recons(dR): yield R
        return _recons(d0)


class MerkleRedBlack(RedBlack):
    """Pass-through context (Identity)
    """
    def __init__(self, H=hash, E=()):
        self.H = H
        super(MerkleRedBlack,self).__init__((E,()))

    def store(self, c, (dL,L), k, (dR,R)):
        return (self.H((c, dL, k, dR)), (c, (dL,L), k, (dR,R)))

    def get(self, (_,D)):
        return D


class HashTableRB(RedBlack):
    def __init__(self, H=hash, E=(), table=None, validate=True):
        self.H = H
        if table is None: table = {}
        self.table = table
        self.cache = {}
        self.validate = validate
        super(HashTableRB,self).__init__(E)

    def store(self, c, dL, k, dR):
        preimage = (c, dL, k, dR)
        try:
            # First check the preimage cache
            return self.cache[preimage]
        except KeyError:
            # Recompute the digest
            digest = self.H(preimage)
            self.cache[preimage] = digest
            try:
                assert self.table[digest] == preimage
            except KeyError:
                self.table[digest] = preimage
            return digest

    def get(self, digest):
        preimage = self.table[digest]
        if self.validate: assert self.H(preimage) == digest
        self.cache[preimage] = digest
        return preimage

    def reconstruct(self, digest):
        def _recons(d0):
            if self.empty(d0): return (),()
            try:
                preimage = self.get(d0)
                (c, dL, k, dR) = preimage
                return d0, (c, (dL, _recons(dL)), k, (dR, _recons(dR)))
            except KeyError:
                if not self.validate: return (),()
                else: raise
        return _recons(digest)


class RecordTraversal(MerkleRedBlack):
    def __init__(self, H=hash, E=(), emit=None):
        """Record a stream of "gets" from a passthrough tree
        """
        super(RecordTraversal,self).__init__(H, E)
        if emit is None:
            self.VO = []
            emit = self.VO.append
        self.emit = emit

    def get(self, (_,D)):
        c, (dL,_), k, (dR,_) = D
        #print 'Record:', (c, dL, k, dR)
        self.emit((c, dL, k, dR))
        return D


class ReplayTraversal(HashTableRB):
    def __init__(self, VO, H=hash, E=()):
        super(ReplayTraversal,self).__init__(H, E)
        self.VO = iter(VO)

    def get(self, d0):
        preimage = self.VO.next()
        #print 'Replay:', d0, preimage
        assert self.H(preimage) == d0
        return preimage
