
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

import math
import itertools

class RedBlack(object):
    def __init__(self, H=hash):
        """
        Args:
             H (optional): a collision-resistant hash function that
                           takes arguments of the form:
                  H(())
                  H((c, dL, k, dR))
        """
        self.H = H
        self.dO = self.digest(())

    def digest(self, D):
        if not D: return self.H(())
        (c, _, (k, dL, dR), _) = D
        return self.H((c, dL, k, dR))

    def record(self, D):
        return RecordTraversal(self.H, D)

    def replay(self, d0, VO):
        return ReplayTraversal(self.H, d0, VO)

    def search(self, q, D):
        T = self.record(D)
        return T.search(q)

    def insert(self, q, D, v=''):
        T = self.record(D)
        return T.reconstruct(T.insert(q, v))

    def delete(self, q, D):
        T = self.record(D)
        return T.reconstruct(T.delete(q))


class Traversal(object):
    def __init__(self, H, d0):
        self.H = H
        self.cache = {}
        self.dO = H(())
        self.d0 = d0

        # TODO: each of the balance operations sometimes produces more 
        # 'proof' than is necessary. For example, if bL2 is a match,
        # then a 'negative proof' for bL1 is unnecessary. Is there a way
        # to resolve this using the same coroutine setup I have?
        R,B,a,b,c,d,x,y,z = 'RBabcdxyz'
        self.bL1 = (B,(R,(R,a,x,b),y,c),z,d), (R,(B,a,x,b),y,(B,c,z,d))
        self.bL2 = (B,(R,a,x,(R,b,y,c)),z,d), (R,(B,a,x,b),y,(B,c,z,d))
        self.bR1 = (B,a,x,(R,(R,b,y,c),z,d)), (R,(B,a,x,b),y,(B,c,z,d))
        self.bR2 = (B,a,x,(R,b,y,(R,c,z,d))), (R,(B,a,x,b),y,(B,c,z,d))

    def balanceL(self, c, dL, k, dR):
        d = self.store(c, dL, k, dR)
        return self.match(self.bL1, d) or self.match(self.bL2, d) or d

    def balanceR(self, c, dL, k, dR):
        d = self.store(c, dL, k, dR)
        return self.match(self.bR1, d) or self.match(self.bR2, d) or d

    def unbalancedL(self, c, dL, k, dR):
        get = self.get
        store = self.store
        balanceL = self.balanceL
        red = lambda (_,dL,x,dR): ('R',dL,x,dR)
        (_c, _dL, _k, _dR) = get(dL)
        if _c == 'B': return balanceL('B',store('R',_dL,_k,_dR),k,dR), c=='B'
        _R = get(_dR)
        assert c == 'B' and _c == 'R' and _R[0] == 'B'
        return store('B',_dL,_k,balanceL('B',store(*red(_R)),k,dR)), False

    def unbalancedR(self, c, dL, k, dR):
        get = self.get
        store = self.store
        balanceR = self.balanceR
        red = lambda (_,dL,x,dR): ('R',dL,x,dR)
        (_c, _dL, _k, _dR) = get(dR)
        if _c == 'B': return balanceR('B',dL,k,store('R',_dL,_k,_dR)), c=='B'
        _L = get(_dL)
        assert c == 'B' and _c == 'R' and _L[0] == 'B'
        return store('B',balanceR('B',dL,k,store(*red(_L))),_k,_dR), False

    def match(self, (lhs, rhs), value):
        # Simulates Haskell pattern matching so we can copy the Okasaki
        # balancing rules directly
        table = {}
        get = self.get
        store = self.store
        dO = self.dO

        def _match(left, value):
            if left in ('R','B'): return left == value
            if isinstance(left, tuple):
                return value != dO and all((_match(*pair) for pair in
                                            itertools.izip(left, get(value))))
            table[left] = value
            return True

        def _constr(right, value):
            if right in ('R','B'): return right
            if isinstance(right, tuple):
                return store(*(_constr(*pair) for pair in
                               zip(right, get(value))))
            return table[right]

        return _constr(rhs, value) if _match(lhs, value) else None

    def store(self, c, dL, k, dR):
        C = (c, dL, k, dR)
        d0 = self.H(C)
        self.cache[d0] = C
        return d0
                                   
    def get(self, d0):
        return self.cache[d0]


    """
    Search, Insert, Delete
    """
    
    def search(self, q):
        d0 = self.d0
        while True:            
            c, dL, k, dR = self.get(d0)
            if dL == dR == self.dO: return k
            d0 = dL if q <= k[0] else dR

    def insert(self, q, v=''):
        balanceL = self.balanceL
        balanceR = self.balanceR
        store = self.store
        get = self.get
        dO = self.dO
        d0 = self.d0

        leaf = store('B', dO, (q,v), dO)
        if d0 == dO: return leaf

        def ins(d0):
            (c, dL, k, dR) = get(d0)
            bD = ('B', dL, k, dR)
            kk, _ = k

            if q == kk:
                raise DuplicateElementError("Can't insert duplicate element")

            if q < kk and dL==dO: return store('R', leaf,  (q,()), store(*bD))
            if q > kk and dR==dO: return store('R', store(*bD), (kk,()), leaf)

            if q < kk: return balanceL(c, ins(dL), (kk,()), dR)
            if q > kk: return balanceR(c, dL, (kk,()), ins(dR))
        
        blacken = lambda (_,dL,k,dR): ('B',dL,k,dR)
        return store(*blacken(get(ins(d0))))


    def delete(self, q):
        unbalancedL = self.unbalancedL
        unbalancedR = self.unbalancedR
        store = self.store
        get = self.get
        dO = self.dO

        def _del(d0):
            """
            This function recursively 'bubbles' up three values
            First, the digest of the subtree after deleting the element
            Second, a flag indicating whether we're unbalanced by one
            Third, the maximum value in the subtree, in case the previous 
                   maximum was the deleted element
            """
            if d0 == dO: return (), False, None
            c, dL, k, dR = get(d0)
            if dL == dR == dO:
                assert q == k[0]
                return dO, True, None
            if q <= k[0]:
                _dL, d, m = _del(dL)
                if _dL == dO: return dR, c=='B', None
                if q == k[0]:
                    assert m is not None
                    k = (m,())
                t = (c, _dL, k, dR)
                if d: return unbalancedR(*t) + (None,)
                else: return store(*t), False, None
            if q  > k[0]:
                _dR, d, m = _del(dR)
                if _dR == dO: return dL, c=='B', k[0]
                t = (c, dL, k, _dR)
                if d: return unbalancedL(*t) + (m,)
                else: return store(*t), False, m

        blacken = lambda (_,dL,x,dR): ('B',dL,x,dR)
        d, _, _ = _del(self.d0)
        return dO if d == dO else store(*blacken(get(d)))


class RecordTraversal(Traversal):
    def __init__(self, H, D):
        c = lambda (c, _, (k, dL, dR), __): (c, dL, k, dR)
        d0 = H(c(D) if D else ())
        super(RecordTraversal,self).__init__(H, d0)
        self.d = {d0: D}
        self.VO = []

    def get(self, d0):
        try:
            return super(RecordTraversal,self).get(d0)
        except KeyError:
            D = self.d[d0]
            (c, L, (k, dL, dR), R) = D
            C = (c, dL, k, dR)
            self.d[dL] = L
            self.d[dR] = R
            self.cache[d0] = C
            self.VO.append(C)
            return C

    def reconstruct(self, d0):
        def _recons(d0):
            if d0 == self.dO: return ()
            if d0 in self.d: return self.d[d0]
            if d0 in self.cache:
                (c, dL, k, dR) = self.cache[d0]
                return (c, _recons(dL), (k, dL, dR), _recons(dR))
        return _recons(d0)


class ReplayTraversal(Traversal):
    def __init__(self, H, d0, VO):
        super(ReplayTraversal,self).__init__(H, d0)
        self.VO = iter(VO)

    def get(self, d0):
        try:
            return super(ReplayTraversal,self).get(d0)
        except KeyError:
            C = self.VO.next()
            assert self.H(C) == d0
            self.cache[d0] = C
            return C
