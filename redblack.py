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
        assert delete(q, R) == delete(q, D)
        assert digest(q, R) == digest(q, D)
        assert query(q, R) == query(q, D)

"""
import math

class RedBlack():
    def __init__(self, H = lambda _: ''):
        def _H(d):
            if not d: return (0, H(()))
            (c, k, dL, dR) = d
            return (max(dL[0] + dR[0], 1), H(d))
        self.H = _H


    def digest(self, D):
        # The hash corresponding to a node is the Hash function applied
        # to the concatenation its children's hashes and its own value
        if not D: return self.H(())
        c, _, (k, dL, dR), _ = D
        return self.H((c, k, dL, dR))


    def verify(self, d0, D, count=None):
        if not D: return True
        if count is None: count = 2*math.ceil(math.log(d0[0]+1,2))
        dO = self.digest(())
        assert d0 == self.digest(D)
        _, L, (_, dL, dR), R = D
        if dL == dR == dO: return True
        assert dL != dO and dR != dO
        assert count > 0
        assert bool(L) ^ bool(R)
        if L: return self.verify(dL, L, None if count is None else count-1)
        if R: return self.verify(dR, R, None if count is None else count-1)


    def search(self, q, D):
        """
        Produce a projection of the tree resulting from searching for 
        element q. 

        forall q and D:
            R = search(q, D)
            assert digest(D) == digest(R)
            assert search(q, D) == search(q, R)
            assert digest(insert(q, D)) == digest(insert(q, R))

        Returns:
            a tuple containing the path through the tree (the values of each
            node visited)
        """
        dO = self.digest(())
        if not D: return ()
        c, L, (k, dL, dR), R = D
        if q <= k and dL != dO:
            if not L:
                print q, k, dO, D
            assert L
            return (c, self.search(q, L), (k, dL, dR), ())
        if q  > k and dR != dO:
            assert R
            return (c, (), (k, dL, dR), self.search(q, R))
        return D


    def query(self, q, D):
        dO = self.digest(())
        while D:
            c, L, (k, dL, dR), R = D
            if dL == dR == dO: return k
            D = L if q <= k else R
        else:
            raise ValueError, "Couldn't descend: %s" % ((c, k, dL, dR),)


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
            if dL == dR == dO:
                if q < k: return balance(('R', ins(L), x, make_black(D)))
                if q > k: return balance(('R', make_black(D), y, ins(R)))

            if q < k: return balance((c, ins(L), y, R))
            if q > k: return balance((c, L, y, ins(R)))

        make_black = lambda (c,a,y,b): ('B',a,y,b)
        return balance(make_black(ins(D)))


    def delete(self, q, D):
        """
        """
        balance = self.balance


    def balance(self, D):
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
            if i == j == 0: return k
            (D,i) = (L,i) if i < j else (R,i-j)
        raise ValueError


    def rank(self, q, D):
        dO = self.digest(())
        i = 0
        while D:
            c, L, (k, dL, dR), R = D
            j = dL[0]
            if dL == dR == dO and q == k: return i+j
            (D,i) = (L,i) if q <= k else (R,i+j)
        raise ValueError


    def size(self, D):
        (N, _) = self.digest(D)
        return N
