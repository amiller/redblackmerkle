"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012

This RedBlack tree is an Authenticated Dictionary [1], based on a balanced 
binary search tree. The tree is balanced strictly, so that all usual
operations can be performed in O(log N) worst-case time. The tree is augmented
with secure hashes for each node (forming a Merkle tree), which allows the
correctness of each operation to be verified in O(log N) time. Only O(1) of
'trusted' state (the Merkle tree root hash) must be maintained by a verifier.

Additionally, the dictionary supports selection of an element by its rank,
which is useful for choosing set elements at random for a Proof-of-Throughput.

Using a balanced tree as an Authenticated Data Structure requires committing
to a particular balancing behavior, since Verification occurs by simulating
the computation on a pruned tree. This implementation uses a combination of
Okasaki style balancing for insert [2] and a more verbose version of 
delete [3,4].


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



Type definitions and common notations:
======================================

RedBlack():
    A RedBlack tree that can be augmented with an arbitrary  'digest' field 
    which is recomputed for consistency at each node. The digests are
    maintained correctly even when elements are inserted and deleted.

    This tree includes a 'size' field which is used to implement the select() 
    and rank() functions.

 ** Note that RedBlack objects simply define functions, the actual data structure 
    D is just a tuple, as described below

D:
    A Node in the tree, especially the root. Of the form:
        (Color, Left, (Element, LeftDigest, RightDigest), Right) = D

    - This is typically abbreviated   (c, L, (k, dL, dR), R) = D
    - Details about the components:
        Color in ('R', 'B'): red and black labels for nodes

        Left, Right: the children, also Nodes,

        LeftDigest, RightDigest:
             digests of the children

        Element: the node values are assumed to be fully ordered

    - () represents the empty tree.
      dO == digest(()) is the empty-digest

VO:
    Each of the following operations produces a Verification Object (VO) along 
    with the result:

        k, VO = search(q, D)
        D, VO = insert(q, D)
        D, VO = delete(q, D)

    The VO contains all of the data for the O(log N) nodes we visited during 
    the computation.

        for (d0, (c, (k, dL, dR))) in VO:
            assert d0 == digest((c, (), (k, dL, dR), ()))

R:
    The Verification Object can be used to assemble a partial 'reconstructed' 
    tree

         R = reconstruct(d0, VO)

    All of the tree operations can be performed on a reconstruction, just as
    though it were an original tree. Operations on a reconstructed tree are
    guaranteed to produce the same results as with the original (or else raise
    an exception).

    These invariants are the basis for a) acorrectness and b) a security claim 
    about this implementation:

         for all D, VO:
             R = reconstruct(d0, VO)

             if search(q, R) succeeds, then
                assert search(q, R) == search(q, D)

             if insert(q, R) succeeds, then
                (R_new, R_VO) = insert(q, R)
                (D_new, D_VO) = insert(q, D)
                assert digest(R_new) == digest(D_new)
                assert R_VO == D_VO

             if delete(q, R) succeeds, then
                (R_new, R_VO) = delete(q, R)
                (D_new, D_VO) = insert(q, D)
                assert digest(R_new) == digest(D_new)
                assert R_VO == D_VO
"""
import math

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

    def record(self, D):
        return RecordTraversal(self.H, D)

    def replay(self, d0, VO):
        return ReplayTraversal(self.H, d0, VO)

    def digest(self, D):
        if not D: return self.H(())
        (c, _, (k, dL, dR), _) = D
        return self.H((c, dL, k, dR))

    def search(self, q, D):
        T = self.record(D)
        return T.search(q)

    def insert(self, q, D):
        T = self.record(D)
        return T.reconstruct(T.insert(q))

    def delete(self, q, D):
        T = self.record(D)
        return T.reconstruct(T.delete(q))


class Traversal(object):
    def __init__(self, H, d0):
        self.H = H
        self.cache = {}
        self.dO = H(())
        self.d0 = d0

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
        dO = self.dO
        table = {}
        get = self.get
        store = self.store

        def _match(left, value):
            if left in ('R','B'): return left == value
            if isinstance(left, tuple):
                return value != dO and all((_match(*pair) for pair in
                                            zip(left, get(value))))
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
            d0 = dL if q <= k else dR

    def insert(self, q):
        """
        Insert element q into the tree.
        Exceptions:
            AssertionError if q is already in the tree.
        """
        balanceL = self.balanceL
        balanceR = self.balanceR
        store = self.store
        get = self.get
        dO = self.dO
        d0 = self.d0

        leaf = store('B', dO, q, dO)
        if d0 == dO: return leaf

        def ins(d0):
            (c, dL, k, dR) = get(d0)
            blackD = ('B', dL, k, dR)

            assert q != k, "Can't insert duplicate element"

            if q < k and dL == dO: return store('R', leaf, q, store(*blackD))
            if q > k and dR == dO: return store('R', store(*blackD), k, leaf)

            if q < k: return balanceL(c, ins(dL), k, dR)
            if q > k: return balanceR(c, dL, k, ins(dR))
        
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
                assert q == k
                return dO, True, None
            if q <= k:
                _dL, d, m = _del(dL)
                if _dL == dO: return dR, c=='B', None
                if q == k:
                    assert m is not None
                    k = m
                t = (c, _dL, k, dR)
                if d: return unbalancedR(*t) + (None,)
                else: return store(*t), False, None
            if q  > k:
                _dR, d, m = _del(dR)
                if _dR == dO: return dL, c=='B', k
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
            

"""
Further augmentations of the digest that provide extra functionality
"""

class SelectRedBlack(RedBlack):
    """
    Include the size of the tree in the digest. This allows for efficient
    selection by rank/index.
    """
    def __init__(self, H=hash):
        def _H(C):
            if not C: return (0, H(C))
            (c, dL, k, dR) = C
            return (dL[0] + dR[0] or 1, H(C))
        super(SelectRedBlack,self).__init__(_H)

        def select(self, i):
            d0 = self.d0
            dO = self.dO
            while True:
                _, dL, k, dR = self.get(d0)
                j = dL[0]
                if i == 0 and dL == dR == dO: return k
                (d0,i) = (dL,i) if i < j else (dR,i-j)
            raise ValueError

        def rank(self, q):
            d0 = self.d0
            dO = self.dO
            i = 0
            while True:
                _, dL, k, dR = self.get(d0)
                j = dL[0]
                if q == k and dL == dR == dO: return i + j
                (d0,i) = (dL,i) if q <= k else (dR,i+j)
            raise ValueError

        def patch(T):
            T.select = lambda i: select(T, i)
            T.rank = lambda i: rank(T, i)
            return T
        self._patch_select = patch

    def record(self, D): 
        return self._patch_select(super(SelectRedBlack,self).record(D))

    def replay(self, d0, VO):
        (N, _) = d0
        assert len(VO) <= 3*math.ceil(math.log(N+1,2))+4
        return self._patch_select(super(SelectRedBlack,self).replay(d0, VO))

    def select(self, i, D): return self.record(D).select(i)
    def rank(self, q, D): return self.record(D).rank(q)
    def size(self, D): return self.digest(D)[0]


class WeightSelectRedBlack(SelectRedBlack):
    """
    Further augment the tree to contain the 'weight' for each tree,
    where the weight is taken from the node key.
    """
    def __init__(self, H=hash):
        super(WeightSelectRedBlack,self).__init__(H)

        dO = H(())
        def _H(d):
            if not d: return (0, (0, H(())))
            (c, dL, k, dR) = d
            W = (k[1] if dL[1][1] == dO and dR[1][1] == dO else 
                 dL[1][0] + dR[1][0])
            return dL[0] + dR[0] or 1, (W, H(d))
        self.H = _H

        def select_weight(self, i):
            d0 = self.d0
            dO = self.dO
            while True:
                c, dL, k, dR = self.get(d0)
                if dL == dR == dO: return k, i
                j = dL[1][0]
                (d0,i) = (dL,i) if i < j else (dR,i-j)
            raise ValueError

        def patch(T): 
            T.select_weight = lambda w: select_weight(T, w)
            return T
        self._patch_weight = patch

    def record(self, D):
        return self._patch_weight(super(WeightSelectRedBlack,self).record(D))

    def replay(self, d0, VO):
        return self._patch_weight(super(WeightSelectRedBlack,self)
                                  .replay(d0, VO))

    def select_weight(self, w, D): return self.record(D).select_weight(w)
