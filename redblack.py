"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012

AuthSelectRedBlack is an authenticated dictionary that allows all typical
operations to be performed in O(log N). The correctness of each operation
can also be verified in O(log N) time by using a Merkle tree. Only O(1) of
state needs to be stored by a Verifier - specifically the Merkle root hash.
Additionally, the dictionary supports selection of an element by its rank,
which is useful for selecting set elements at random.


This implementation uses Red-Black Merkle trees as described in [1], and
in particular the Okasaki style balancing rules [2].


Type definitions and common notations:
======================================

RedBlack():
    A general purpose RedBlack tree that is easy to augment because it allows
    an arbitrary 'digest' field to be computed for each node. The digest is
    a pure function of the values of its children - this means the digests are
    maintained correctly even when nodes are inserted and deleted.

AuthSelectRedBlack(RedBlack):
    This upgrades the RedBlack tree to a Merkle tree by including the hash of
    each of its children nodes in the digest. It also adds a 'size' field which
    is used to implement the select() and rank() functions.

 ** Note that for both RedBlack and AuthSelectRedBlack, these objects simply
    define functions, the actual data structure D is just a tuple, as described 
    below

D:
    A Node in the tree, especially the root. Of the form:
        (Color, Left, (Element, LeftDigest, RightDigest), Right) = D

    - This is typically abbreviated   (c, L, (k, dL, dR), R) = D
    - Details about the components:
        Color in ('R', 'B'): red and black labels for nodes

        Left, Right: the children, also Nodes,

        LeftDigest, RightDigest:
             digests of the children.
                 H( dL || k || dR ) is the digest for each Node.

        Element: the node values are assumed to be fully ordered

    - () represents the empty tree.

R:
    A stubby tree reconstructed from a Verification Object. Edges that have
    become stubs were not visited during the search that produced the VO, so
    they won't be visted when simulating/replaying the operation.

P:
    A Verification Object. This is just a trace through the merkle tree. It's
    a tuple of node values, of the form:

         (Color, Key, LeftDigest, RightDigest) = P[0]
         abbreviated (c, k, dL, dR)
    
    where the first element is the root of the tree, and the last element
    is (_, Element, _, _) if Element was found in the tree.


Correctness invariant for augmenting the tree with 'digest'
===========================================================

    forall q and D:
        R = reconstruct(search(q, D))
        assert digest(D) == digest(R)
        assert search(q, D) == search(q, R)
        assert digest(insert(q, D)) == digest(insert(q, R))

"""

class RedBlack():
    def __init__(self, H = lambda _: ''):
        self.H = H


    def digest(self, D):
        # The hash corresponding to a node is the Hash function applied
        # to the concatenation its children's hashes and its own value
        if not D: return self.H(None)
        c, _, (k, dL, dR), _ = D
        return self.H((c, k, dL, dR))


    def search(self, q, D):
        """
        Search the binary tree from the root to either a node containing q
        or a leaf node.

        Returns:
            a tuple containing the path through the tree (the values of each
            node visited)
        """
        result = []
        while D:
            c, L, (k, dL, dR), R = D
            result.append((c, (k, dL, dR)))
            if q == k: break
            D = L if q < k else R
        return tuple(result)


    def query(self, q, D):
        P = self.search(q, D)
        if not P: return None, P
        (c,(k, _, _)) = P[-1]
        return k if k == q else None, P


    def reconstruct(self, P):
        """
        Reconstruct a partial view of a tree (a path from root to leaf)
        given a proof object consisting of the colors and values from
        the path.

        forall q and D:
            R = reconstruct(search(q, D))
            assert digest(D) == digest(R)
            assert search(q, D) == search(q, R)
            assert digest(insert(q, D)) == digest(insert(q, R))
        """
        P = iter(P)
        try:
            (c, (k, dL, dR)) = P.next()
        except StopIteration:
            return ()

        child = self.reconstruct(P)
        if not child:
            return (c, (), (k, dL, dR), ())

        else:
            _, _, (_k, _, _), _ = child
            if _k <= k:
                assert dL == self.digest(child)
                return (c, child, (k, dL, dR), ())
            else:
                assert dR == self.digest(child)
                return (c, (), (k, dL, dR), child)


    def insert(self, q, D):
        """
        Insert element x into the tree.
        Exceptions:
            AssertionError if x is already in the tree.
        """
        balance = self.balance
        x = (q, self.digest(None), self.digest(None))

        def ins(D):
            # Trivial case
            if not D: return ('R', (), x, ())
            c, a, y, b = D
            (p, dL, dR) = y

            # Element already exists (insert is idempotent)
            assert q != p

            # Leaf node found (this will become the parent)
            if q < p: return balance((c, ins(a), y, b))
            if q > p: return balance((c, a, y, ins(b)))

        make_black = lambda (c,a,y,b): ('B',a,y,b)
        return balance(make_black(ins(D)))


    def delete(self, q, D):
        """
        """
        balance = self.balance


    def balance(self, D):
        # This is the simplest way I could think of simulating the 
        # pattern matching from Haskell. The point is to be able to
        # use the very elegant statement from the Okasaki paper [1]
        # (see the return statement in this function)
        # TODO: find a more elegant way to write this
        def refresh(D):
            # Recompute the hashes for each node, but only if the children
            # are available. Otherwise, we assume the current value is correct.
            c, L, (k, dL, dR), R = D
            if L: dL = self.digest(L)
            if R: dR = self.digest(R)
            return (c, L, (k, dL, dR), R)

        R,B,a,b,c,d,x,y,z,m,n,o,p,_ = 'RBabcdxyzmnop_'
        blank = self.digest(None)
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
                return (R,(B,a,(x,m,n),b),(y,blank,blank),(B,c,(z,o,p),d))
            else: return None

        return refresh(match(B,(R,(R,a,(x,m,n),b),(y,_,o),c),(z,_,p),d) or
                       match(B,(R,a,(x,m,_),(R,b,(y,n,o),c)),(z,_,p),d) or
                       match(B,a,(x,m,_),(R,(R,b,(y,n,o),c),(z,_,p),d)) or
                       match(B,a,(x,m,_),(R,b,(y,n,_),(R,c,(z,o,p),d))) or
                       D)


class AuthSelectRedBlack(RedBlack):

    def __init__(self, H = lambda _: ''):
        size = lambda x: 0 if not x else 1 + x[2][1] + x[3][1]
        RedBlack.__init__(self, lambda x: (H(x), size(x)))
        
    def select(self, i, D):
        P = []
        while D:
            c, L, (k, dL, dR), R = D
            P.append((c, (k, dL, dR)))
            j = dL[1]
            if i == j: 
                return k, tuple(P)
            (D,i) = (L,i) if i < j else (R,i-j-1)
        raise ValueError

    def rank(self, q, D):
        i = 0
        P = []
        while D:
            c, L, (k, dL, dR), R = D
            P.append((c, (k, dL, dR)))
            j = dL[1]
            if q == k: return i+j
            (D,i) = (L,i) if q < k else (R,i+j+1)
        raise ValueError
                    
    def verify(self, d0, v, i, P):
        _, N = d0
        import math
        assert len(P) <= 2*math.ceil(math.log(N+1,2))
        R = self.reconstruct(P)
        assert self.digest(R) == d0
        _v, _ = self.select(i, R)
        assert _v == v
        return True

    def size(self, D):
        (_, N) = self.digest(D)
        return N
