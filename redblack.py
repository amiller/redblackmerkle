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
    """

    """

    def __init__(self, H=hash):
        """
        Args:
             H (optional): a collision-resistant hash function that
                           takes arguments of the form:             
                  H(())
                  H((c, k, dL, dR))
        """
        self.H = H
        self.dO = self.digest(())


    def digest(self, D):
        if not D: return self.H(())
        (c, _, (k, dL, dR), _) = D
        return self.H((c, k, dL, dR))

        
    """
    Methods for traversing the tree and collecting/replaying proofs
    """

    def reconstruct(self, d0, VO):
        table = dict(VO)
        assert len(table) == len(VO)
        def _recons(d0):
            if d0 == self.dO or d0 not in table: return ()
            (c, (k, dL, dR)) = table[d0]
            assert self.digest((c, (), (k, dL, dR), ())) == d0
            return (c, _recons(dL), (k, dL, dR), _recons(dR))
        return _recons(d0)


    def walk(self, D):
        while True: _, D = yield D


    def tree_to_dict(self, D):
        d = {}
        while D:
            (c, _, (k, dL, dR), _) = D
            d[self.digest(D)] = (c, k, dL, dR)
        return d


    def getter(self, D):
        return self.record(D)[:2]

    def record(self, D):
        VO = []
        cache = {}
        prefetch = {digest(D): D}

        def store(D): 
            d0 = self.H(D)
            cache[d0] = D
            return d0

        def get(d0):
            if d0 in cache: return cache[d0]
            D = prefetch[d0]
            (c, L, (k, dL, dR), R) = D
            D = (c, k, dL, dR)
            prefetch[dL] = L
            prefetch[dR] = R
            cache[d0] = D
            VO.append(D)
            return D

        return (get, store), VO


    def replay(self, d0, VO):
        H = self.H
        it = iter(VO)
        cache = {}
        def get_and_verify(d0):
            if d0 in cache: return cache
            (_d0, D) = it.next()
            assert _d0 == d0 == H(D)
            cache[d0] = D
            return D
        return get_and_verify


    def record_walk(self, D):
        VO = []
        def walk(D):
            while True:
                d0, D = yield D
                (c, _, (k, dL, dR), _) = D
                VO.append((d0, (c, k, dL, dR)))
        return walk(D), VO


    def replay_walk(self, d0, VO):
        digest = self.digest
        it = iter(VO)
        def walk(d0):
            yield None
            try:
                while True:
                    _, (c,x) = it.next()
                    D = (c, (), x, ())
                    assert digest(D) == d0
                    d0, _ = yield D

            except StopIteration:
                yield D
        return walk(d0)


    """
    Search, Insert, Delete
    """
    
    def search(self, q, d0, get):
        """
        """
        if not callable(get): get = self.getter(get)
        while True:            
            c, k, dL, dR = get(d0)
            if dL == dR == self.dO: return k
            d0 = dL if q <= k else dR


    def insert(self, q, (get, tree)):
        """e
        Insert element q into the tree.
        Exceptions:
            AssertionError if q is already in the tree.
        """
        balance = self.balance
        dO = self.dO
        H = self.H
        leaf = store(('B', q, dO, dO))
        if d0 == dO: return leaf

        def ins(d0):
            (c, k, dL, dR) = get(d0)
            blackD = ('B', k, dL, dR)

            assert q != k, "Can't insert duplicate element"

            if q < k and dL == dO: return tree('R', q, leaf, store(blackD))
            if q > k and dR == dO: return tree('R', q, store(blackD), leaf)

            if q < k: return balance((c, ins(dL), y, dR))
            if q > k: return balance((c, L, y, ins(dR)))
        
        blacken = lambda (_,k,dL,dR): ('B',k,dL,dR)
        return H(blacken(get(ins(d0))))


    def delete(self, q, walk):
        balance = self.balance
        if isinstance(walk, tuple): walk = self.walk(walk)
        D = walk.next()
        dO = self.digest(())
        d0 = self.digest(D)

        def rehash(D):
            """
            Recompute the digests only when the subtrees are available. 
            Otherwise use the initial values.
            """
            if not D: return ()
            c, L, (k, dL, dR), R = D
            if L: dL = self.digest(L)
            if R: dR = self.digest(R)
            return (c, L, (k, dL, dR), R)

        def unbalancedL((c, L, x, R)):
            (k, dL, dR) = x
            (lc, lL, lx, lR) = L
            lL = walk.send((lx[1], lL))
            lR = walk.send((lx[2], lR))
            if lc == 'B':
                return balance(('B', ('R', lL, lx, lR), x, R)), c=='B'
            lRL = walk.send((lR[2][1], lR[1]))
            lRR = walk.send((lR[2][2], lR[3]))
            lR = (lR[0], lRL, lR[2], lRR)
            assert c == 'B' and lc == 'R' and lR[0] == 'B'
            return rehash(('B', lL, lx, balance(('B', turnR(lR), x, R)))), False

        def unbalancedR((c, L, x, R)):
            (k, dL, dR) = x
            (rc, rL, rx, rR) = R
            rL = walk.send((rx[1], rL))
            rR = walk.send((rx[2], rR))
            if rc == 'B':
                return balance(('B', L, x, ('R', rL, rx, rR))), c=='B'
            rLL = walk.send((rL[2][1], rL[1]))
            rLR = walk.send((rL[2][2], rL[3]))
            rL = (rL[0], rLL, rL[2], rLR)
            assert c == 'B' and rc == 'R' and rL[0] == 'B'
            return rehash(('B', balance(('B', L, x, turnR(rL))), rx, rR)), False

        def del_(d0, D):
            """
            This function recursively 'bubbles' up three values
            First, the result of each subtree after deleting the element
            Second, a flag indicating whether we're short by one black path
            Third, the maximum value in the tree in case deleting changes it
            """
            if d0 == dO: return (), False, None
            c, L, (k, dL, dR), R = walk.send((d0, D))
            if dL == dR == dO:
                assert q == k
                return (), True, None
            if q <= k:
                #if dL != dO: assert L
                R = walk.send((dR, R))
                L_, d, m = del_(dL, L)
                if not L_: return R, c=='B', None
                if q == k:
                    assert m is not None
                    k = m
                t = rehash((c, L_, (k, dO, dO), R))
                return unbalancedR(t) + (None,) if d else (t, False, None)
            if q  > k:
                #if dR != dO: assert R
                L = walk.send((dL, L))
                R_, d, m = del_(dR, R)
                if not R_: return L, c=='B', k
                t = rehash((c, L, (k, dO, dO), R_))
                return unbalancedL(t) + (m,) if d else (t, False, m)

        turnR = lambda (_, L, x, R): ('R', L, x, R)
        turnB = lambda (_, L, x, R): ('B', L, x, R)
        turnB_ = lambda x: () if not x else turnB(x)

        return rehash(turnB_(del_(d0, D)[0]))

    def balanceL(self, (c, k, dL, dR), L, R):
        
        if c == 'B':
            return (
        
        if c = 
        balanceL B (Fork R (Fork R a x b) y c) z d = Fork R (Fork B a x b) y (Fork B c z d)
        balanceL B (Fork R a x (Fork R b y c)) z d = Fork R (Fork B a x b) y (Fork B c z d)
        balanceL k a x b                           = Fork k a x b


    def balance(self, d0):
        if not D: return ()
        def rehash(D):
            # Recompute the hashes for each child, but only if the child is
            # is available. Otherwise, we leave the current value unchanged.
            c, L, (k, dL, dR), R = D
            if L: dL = self.digest(L)
            if R: dR = self.digest(R)
            return (c, L, (k, dL, dR), R)

        R,B,a,b,c,d,x,y,z,m,n,o,p,_ = 'RBabcdxyzmnop_'
        dO = self.digest(())

        # This is the simplest way I could think of simulating the 
        # pattern matching from Haskell. The point is to be able to
        # use the very elegant statement from the Okasaki paper [1]
        # (see the return statement in this function)
        # TODO: find a more elegant way to write this
        #       benchmarking confirms this is the slowest part
        def match(*args):
            table = {}
            def _match(left,right):
                if left in ('R','B'): return left == right
                if isinstance(left, tuple):
                    return len(right) == len(left) and \
                        all((_match(*pair) for pair in zip(left, right)))
                assert left in 'abcdxyzmnop_'
                table[left] = right
                return True

            if _match(args, rehash(D)):
                a,b,c,d,x,y,z,m,n,o,p = map(table.get, 'abcdxyzmnop')
                return (R,(B,a,(x,m,n),b),(y,dO,dO),(B,c,(z,o,p),d))
            else: return None

        return rehash(match(B,(R,(R,a,(x,m,n),b),(y,_,o),c),(z,_,p),d) or
                       match(B,(R,a,(x,m,_),(R,b,(y,n,o),c)),(z,_,p),d) or
                       match(B,a,(x,m,_),(R,(R,b,(y,n,o),c),(z,_,p),d)) or
                       match(B,a,(x,m,_),(R,b,(y,n,_),(R,c,(z,o,p),d))) or
                       D)

    def replay_proofs(self, d0, VOs):
        digest = self.digest
        reconstruct = self.reconstruct
        it = iter(VOs)
        def proof(d0):
            try:
                while True:
                    VO = it.next()
                    D, _VO = yield reconstruct(d0, VO)
                    assert VO == _VO
                    d0 = digest(D)
            except StopIteration:
                yield D
        return proof(d0)

    def record_proofs(self, D):
        VOs = []
        def proof(D):
            while True:
                D, VO = yield D
                VOs.append(VO)
        return proof(D), VOs


"""
Further augmentations of the digest that provide extra functionality
"""

class SelectRedBlack(RedBlack):
    """
    Include the size of the tree in the digest. This allows for efficient
    selection by rank/index.
    """
    def __init__(self, H=hash):
        def _H(d):
            if not d: return (0, H(()))
            (c, k, dL, dR) = d
            return (dL[0] + dR[0] or 1, H(d))
        super(SelectRedBlack,self).__init__(_H)

    def reconstruct(self, d0, VO):
        # The worst case scenario for a VO depends on the size of the tree
        # TODO: Work out this expression with a compelling diagram
        (N, _) = d0
        assert len(VO) <= 3*math.ceil(math.log(N+1,2))+4
        return super(SelectRedBlack,self).reconstruct(d0, VO)

    def select(self, i, walk):
        if isinstance(walk, tuple): walk = self.walk(walk)
        D = walk.next()
        d0 = self.digest(D)
        dO = self.digest(())
        while True:
            c, L, (k, dL, dR), R = walk.send((d0, D))
            j = dL[0]
            if i == 0 and dL == dR == dO: return k
            (D,i) = (L,i) if i < j else (R,i-j)

    def rank(self, q, walk):
        if isinstance(walk, tuple): walk = self.walk(walk)
        D = walk.next()
        d0 = self.digest(D)
        dO = self.digest(())
        i = 0
        while True:
            _, L, (k, dL, dR), R = walk.send((d0, D))
            j = dL[0]
            if q == k and dL == dR == dO: return i + j
            (D,d0,i) = (L,dL,i) if q <= k else (R,dR,i+j)

    def size(self, D):
        (N, _) = self.digest(D)
        return N


class WeightSelectRedBlack(SelectRedBlack):
    """
    Further augment the tree to contain the 'weight' for each tree,
    where the weight is taken from the node key.
    """
    def __init__(self, H=hash):
        dO = H(())
        def _H(d):
            if not d: return (0, (0, H(())))
            (c, k, dL, dR) = d
            W = (k[1] if dL[1][1] == dO and dR[1][1] == dO else 
                 dL[1][0] + dR[1][0])
            return dL[0] + dR[0] or 1, (W, H(d))
        super(SelectRedBlack,self).__init__(_H)


    def select_weight(self, i, D):
        dO = self.digest(())
        while D:
            c, L, (k, dL, dR), R = D
            j = dL[1][0]
            if dL == dR == dO: return k, i
            (D,i) = (L,i) if i < j else (R,i-j)
        raise ValueError
