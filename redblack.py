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
        R = reconstruct(search(q, D))
        assert digest(D) == digest(R)
        assert search(q, D) == search(q, R)
        assert digest(insert(q, D)) == digest(insert(q, R))

    forall q, D, R:
        assert verify(digest(D), R)   # Precondition 1
        assert search(q, R)           # Precondition 2

        # If the above preconditions hold, then the
        # following are guaranteed to succeed:

        assert search(q, R) == search(q, D)
        assert insert(q, R) == insert(q, D)
        assert digest(q, R) == digest(q, D)
        assert query(q, R) == query(q, D)

"""
import math

class RedBlack():
    def __init__(self, H = lambda _: ''):
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


    def verify(self, d0, D):
        """
        TODO: enforce the invariant that D must contain
              no more than 
                   count = 2*math.ceil(math.log(d0[0]+1,2)) + 2
              elements for it to be a plausible result from search()
              or search_delete()
        """
        if not D: return True
        dO = self.digest(())
        _, L, (_, dL, dR), R = D
        if L: assert self.verify(dL, L)
        if R: assert self.verify(dR, R)
        return True


    def search(self, q, D):
        """
        Produce a projection of the tree resulting from searching for 
        element q.

        forall q and D:
            R = search(q, D)
            assert digest(D) == digest(R)
            assert search(q, D) == search(q, R)
            assert query(q, D) == query(q, R)
            assert digest(insert(q, D)) == digest(insert(q, R))

        Returns:
            a tuple containing the path through the tree (the values of each
            node visited)
        """
        dO = self.digest(())
        if not D: return ()
        c, L, x, R = D
        (k, dL, dR) = x
        if q <= k:
            if dL != dO: assert L
            return (c, self.search(q, L), x, ())
        if q > k: 
            if dR != dO: assert R
            return (c, (), x, self.search(q, R))


    def query(self, q, D, K=lambda x:x):
        dO = self.digest(())
        while D:
            c, L, (k, dL, dR), R = D
            if dL == dR == dO: return k
            D = L if q <= K(k) else R
        else:
            raise ValueError, "Couldn't descend"


    def insert(self, q, D):
        """
        Insert element q into the tree.
        Exceptions:
            AssertionError if q is already in the tree.
        """
        balance = self.balance
        dO = self.digest(())
        x = (q, dO, dO)

        def ins(D):
            if not D: return ('B', (), x, ())
            c, L, y, R = D
            (k, dL, dR) = y

            assert q != k, "Can't insert element that is already present"

            if q < k and dL == dO: return balance(('R', ins(L), x, black(D)))
            if q > k and dR == dO: return balance(('R', black(D), y, ins(R)))

            if q < k: return balance((c, ins(L), y, R))
            if q > k: return balance((c, L, y, ins(R)))

        black = lambda (c,a,y,b): ('B',a,y,b)
        return balance(black(ins(D)))


    def search_delete(self, q, D):
        """
        Return a projection of the tree that can be used to simulate a
        delete() operation. This is just like performing a delete, except
        we accumulate just the nodes we touch at each step. 
        """
        balance = self.balance
        pass


    def delete(self, q, D):
        balance = self.balance
        dO = self.digest(())

        def refresh(D):
            c, L, (k, dL, dR), R = D
            if L: dL = self.digest(L)
            if R: dR = self.digest(R)
            return (c, L, (k, dL, dR), R)

        def unbalancedL((c, L, x, R)):
            (k, dL, dR) = x
            (lc, lL, lx, lR) = L
            if lc == 'B': return balance(('B', turnR(L), x, R)), c=='B'
            assert c == 'B' and lc == 'R' and lR[0] == 'B'
            return refresh(('B', lL, lx, balance(('B', turnR(lR), x, R)))), False

        def unbalancedR((c, L, x, R)):
            (k, dL, dR) = x
            (rc, rL, rx, rR) = R
            if rc == 'B': return balance(('B', L, x, turnR(R))), c=='B'
            assert c == 'B' and rc == 'R' and rL[0] == 'B'
            return refresh(('B', balance(('B', L, x, turnR(rL))), rx, rR)), False

        def del_(D):
            """
            This function recursively 'bubbles' up three values
            First, the result of each subtree after deleting the element
            Second, a flag indicating whether we're short by one black path
            Third, the maximum value in the tree in case deleting changes it
            """
            if not D: return (), False, None
            c, L, (k, dL, dR), R = D
            if dL == dR == dO:
                assert q == k
                return (), True, None
            if q <= k:
                if dL != dO: assert L
                L_, d, m = del_(L)
                if not L_: return R, c=='B', None
                if q == k: 
                    assert m is not None
                    k = m
                t = refresh((c, L_, (k, dO, dO), R))
                return unbalancedR(t) + (None,) if d else (t, False, None)
            if q  > k:
                if dR != dO: assert R
                R_, d, m = del_(R)
                if not R_: return L, c=='B', k
                t = refresh((c, L, (k, dO, dO), R_))
                return unbalancedL(t) + (m,) if d else (t, False, m)

        turnR = lambda (_, L, x, R): ('R', L, x, R)
        turnB = lambda (_, L, x, R): ('B', L, x, R)
        turnB_ = lambda x: () if not x else turnB(x)

        def blackify(x):
            if not x: return (), True
            (c,a,y,b) = x
            return ('B',a,y,b), c=='B'

        return balance(turnB_(del_(D)[0]))



    def balance(self, D):
        if not D: return ()
        def refresh(D):
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

            if _match(args, refresh(D)):
                a,b,c,d,x,y,z,m,n,o,p = map(table.get, 'abcdxyzmnop')
                return (R,(B,a,(x,m,n),b),(y,dO,dO),(B,c,(z,o,p),d))
            else: return None

        return refresh(match(B,(R,(R,a,(x,m,n),b),(y,_,o),c),(z,_,p),d) or
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
