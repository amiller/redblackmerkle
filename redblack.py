"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012

AuthSelectRedBlack is an authenticated dictionary that allows all typical
operations to be performed in O(log N). The correctness of each operation
can also be verified in O(log N) time by using a Merkle tree. Only O(1) of
state needs to be stored by a Verifier, specifically the Merkle root hash.
Additionally, the dictionary supports selection of an element by its rank,
which is useful for choosing set elements at random, as is necessary for a
Proof-of-Throughput.


This implementation uses Red-Black Merkle trees as described in [1], and
in particular the Okasaki style balancing rules [2]. Here's why I haven't
implemented Delete yet [3].


[1] Persistent Authenticated Dictionaries and Their Applications
    http://cs.brown.edu/people/aris/pubs/pad.pdf
[2] http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps
[3] Missing method: How to delete from Okasaki's red-black trees
    http://matt.might.net/articles/red-black-delete/


Type definitions and common notations:
======================================

RedBlack():
    A general purpose RedBlack tree that is easy to augment because it allows
    an arbitrary 'digest' field to be computed for each node. The digest is
    a pure function of the values of its children - this means the digests are
    maintained correctly even when nodes are inserted and deleted.

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

R:
    The result of search(q, D) is a Verification Object, comprising a stubby
    tree of the O(log N) nodes that were visited during the search.

    Invariants:

    forall q and D:
        d0 = digest(D)
        _, VO = search(q, D)
        R = reconstruct(digest(D), VO)
        assert digest(D) == digest(R)
        assert search(q, D) == search(q, R)
        assert digest(insert(q, D)[0]) == digest(insert(q, R)[0])

    forall q, D, VO:
        R = reconstruct(digest(D), VO) # Precondition 1
        assert q == search(q, R)[0]    # Precondition 2

        # If the above preconditions hold, then the
        # following are guaranteed to succeed:

        assert digest(R) == digest(D)
        assert search(q, R) == search(q, D)
        assert digest(insert(q, R)[0]) == digest(insert(q, D)[0])
        assert rank(q, R) == rank(q, D)
        assert select(rank(q, R), R) == select(rank(q, D), D)

"""
import math

class RedBlack():
    def __init__(self, H = lambda x: '' if not x else x[1]):
        def _H(d):
            if not d: return (0, H(()))
            (c, k, dL, dR) = d
            return (dL[0] + dR[0] or 1, H(d))
        self.H = _H


    def digest(self, D):
        # The hash corresponding to a node is the Hash function applied
        # to the concatenation its children's hashes and its own value
        if not D: return self.H(())
        c, _, (k, dL, dR), _ = D
        return self.H((c, k, dL, dR))


    def reconstruct(self, d0, VO):
        (N, _) = d0
        dO = self.digest(())
        # The worst case scenario for a VO depends on the size of the tree
        # TODO: Work out this expression with a compelling diagram
        assert len(VO) <= 3*math.ceil(math.log(N+1,2))
        table = dict(VO)
        def _recons(d0):
            if d0 == dO or d0 not in table: return ()
            (c, (k, dL, dR)) = table[d0]
            assert self.digest((c, (), (k, dL, dR), ())) == d0
            return (c, _recons(dL), (k, dL, dR), _recons(dR))
        return _recons(d0)


    def _stash(self):
        VO = []
        def stash(dD, D):
            (c, _, x, _) = D
            VO.append((dD, (c, x)))
            return D
        return stash, VO


    def search(self, q, D):
        """
        """
        dO = self.digest(())
        d0 = self.digest(D)
        stash, VO = self._stash()
        while True:
            stash(d0,D)
            c, L, (k, dL, dR), R = D
            if dL == dR == dO: return k, tuple(VO)
            (d0,D) = (dL,L) if q <= k else (dR,R)


    def insert(self, q, D):
        """
        Insert element q into the tree.
        Exceptions:
            AssertionError if q is already in the tree.
        """
        balance = self.balance
        dO = self.digest(())
        d0 = self.digest(D)
        x = (q, dO, dO)
        leaf = ('B', (), x, ())
        if not D: return leaf, ()
        stash, VO = self._stash()
        stash(d0, D)

        def ins(D):
            if not D: return leaf
            c, L, y, R = D
            (k, dL, dR) = y

            assert q != k, "Can't insert duplicate element"

            if q < k and dL == dO: return balance(('R', leaf, x, black(D)))
            if q > k and dR == dO: return balance(('R', black(D), y, leaf))

            if q < k: return balance((c, ins(stash(dL,L)), y, R))
            if q > k: return balance((c, L, y, ins(stash(dR,R))))

        black = lambda (c,a,y,b): ('B',a,y,b)
        return balance(black(ins(D))), tuple(VO)


    def delete(self, q, D):
        balance = self.balance
        dO = self.digest(())
        d0 = self.digest(D)
        stash, VO = self._stash()
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
            stash(lx[1], lL)
            stash(lx[2], lR)
            if lc == 'B': return balance(('B', turnR(L), x, R)), c=='B'
            assert c == 'B' and lc == 'R' and lR[0] == 'B'
            return rehash(('B', lL, lx, balance(('B', turnR(lR), x, R)))), False

        def unbalancedR((c, L, x, R)):
            (k, dL, dR) = x
            (rc, rL, rx, rR) = R
            stash(rx[1], rL)
            stash(rx[2], rR)
            if rc == 'B': return balance(('B', L, x, turnR(R))), c=='B'
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
            c, L, (k, dL, dR), R = stash(d0, D)
            if dL == dR == dO:
                assert q == k
                return (), True, None
            if q <= k:
                if dL != dO: assert L
                stash(dR, R)
                L_, d, m = del_(dL, L)
                if not L_: return R, c=='B', None
                if q == k:
                    assert m is not None
                    k = m
                t = rehash((c, L_, (k, dO, dO), R))
                return unbalancedR(t) + (None,) if d else (t, False, None)
            if q  > k:
                if dR != dO: assert R
                stash(dL, L)
                R_, d, m = del_(dR, R)
                if not R_: return L, c=='B', k
                t = rehash((c, L, (k, dO, dO), R_))
                return unbalancedL(t) + (m,) if d else (t, False, m)

        turnR = lambda (_, L, x, R): ('R', L, x, R)
        turnB = lambda (_, L, x, R): ('B', L, x, R)
        turnB_ = lambda x: () if not x else turnB(x)

        return rehash(turnB_(del_(d0, D)[0])), tuple(VO)


    def balance(self, D):
        if not D: return ()
        def rehash(D):
            # Recompute the hashes for each node, but only if the children
            # are available. Otherwise, we assume the current value is correct.
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


    def select(self, i, D):
        dO = self.digest(())
        while D:
            c, L, (k, dL, dR), R = D
            j = dL[0]
            if i == 0 and dL == dR == dO: return k
            (D,i) = (L,i) if i < j else (R,i-j)
        raise ValueError


    def rank(self, q, D):
        dO = self.digest(())
        i = 0
        while D:
            c, L, (k, dL, dR), R = D
            j = dL[0]
            if q == k and dL == dR == dO: return i + j
            (D,i) = (L,i) if q <= k else (R,i+j)
        raise ValueError


    def size(self, D):
        (N, _) = self.digest(D)
        return N
