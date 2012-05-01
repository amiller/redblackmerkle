from collections import namedtuple
import json


# Okasaki method for red-black tree
"""
This is based on the Persistent Authenticated Dictionary, and the
Okasaki method for Red-Black trees.

I tried to factor the red-black tree logic from the Merkle tree
stuff as much as possible. This allows me to test the balancing behavior
separately from the hash.

The problem is I have to include this
'recompute' function f as a parameter to all my red-black tree functino.

"""

def AuthRedBlack(H = lambda _: ''):
    """
    Returns:
        dict with functions
    """    
    def digest(D):
        # The hash corresponding to a node is the Hash function applied
        # to the concatenation its children's hashes and its own value
        if not D: return ''
        c, _, (k, dL, dR), _ = D
        return H((c, k, dL, dR))


    def rehash(D):
        # Recompute the hashes for each node, but only if the children
        # are available. Otherwise, we assume the current value is correct.
        c, L, (k, dL, dR), R = D
        if L: dL = digest(L)
        if R: dR = digest(R)
        return (c, L, (k, dL, dR), R)


    def balance(D):
        # This is the simplest way I could think of simulating the 
        # pattern matching from Haskell. The point is to be able to
        # use the very elegant statement from the Okasaki paper [1]
        # (see the return statement in this function)
        # TODO: find a more elegant way to write this
        R,B,a,b,c,d,x,y,z,m,n,o,p,_ = 'RBabcdxyzmnop_'
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

            if _match(args, D):
                a,b,c,d,x,y,z,m,n,o,p = map(table.get, 'abcdxyzmnop')
                return (R,(B,a,(x,m,n),b),(y,'',''),(B,c,(z,o,p),d))
            else: return None

        return rehash(match(B,(R,(R,a,(x,m,n),b),(y,_,o),c),(z,_,p),d) or
                      match(B,(R,a,(x,m,_),(R,b,(y,n,o),c)),(z,_,p),d) or
                      match(B,a,(x,m,_),(R,(R,b,(y,n,o),c),(z,_,p),d)) or
                      match(B,a,(x,m,_),(R,b,(y,n,_),(R,c,(z,o,p),d))) or
                      D)


    def search(q, D):
        """
        Return a proof object for a search, consisting of the 
        values of the nodes visited during a binary search.
        """
        if not D: return ()

        c, left, k, right = D
        if not left and not right: # Leaf node
            return ((c,k),)

        child = left if q <= k[0] else right # Inner node
        return ((c,k),) + search(q, child)


    def reconstruct(proof):
        """
        Reconstruct a partial view of a tree (a path from root to leaf)
        given a proof object consisting of the colors and values from
        the path.

        Invariant:
            forall q and D:
            search(1, reconstruct(search(q, D))) == search(q, D)
        """
        if not proof: return ()

        (c, k), tail = proof[0], proof[1:]
        if not tail:
            return rehash((c, (), k, ()))

        child = reconstruct(tail)
        _, _, _k, _ = child
        return rehash((c, child, k, ()) if _k[0] <= k[0] else 
                      (c, (), k, child))


    def insert(q, D):
        """
        Insert element x into the tree.
        Exceptions:
            AssertionError if x is already in the tree.
        """
        x = (q, '', '')

        def ins(D):
            # Trivial case
            if not D: return ('B', (), x, ())

            # Element already exists (insert is idempotent)
            c, a, y, b = D
            if q == y[0]: return D

            # Leaf node found (this will become the father)
            if q < y[0] and not a:
                return balance(rehash(('R', ins(a), x, make_black(D))))

            if q > y[0] and not b: 
                return balance(rehash(('R', make_black(D), y, ins(b))))

            # Otherwise recurse
            if q < y[0]: return balance((c, ins(a), y, b))
            if q > y[0]: return balance((c, a, y, ins(b)))

        def make_black(D):
            (c, a, y, b) = D
            return ('B', a, y, b)

        return rehash(make_black(ins(D)))


    def delete(q, D):
        """
        """
        pass

    return locals()


# Now we begin with the Merkle tree specialization
H = lambda x: SHA256.new(x).hexdigest()


def verify_search(q, d0, proof):
    r = reconstruct(proof)
    assert digest(r) == d0
    assert search(q, r) == proof
    return True


def refresh(q, d0, proof):
    # Return the digest for the new tree
    r = reconstruct(proof)
    assert digest(r) == d0
    assert search(q, r) == proof
    return digest(insert(q, r))


def verify_update(q, d0, d1, proof):
    assert refresh(q, d0, proof) == d1


def update(u, D):
    proof = search(u, D)
    return insert(u, D)
