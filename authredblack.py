"""
An authenticated search structure [1] using Okasaki-style red-black trees [2].

[1] http://cs.brown.edu/people/aris/pubs/pad.pdf
[2] http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps

"""

class AuthRedBlack():
    def __init__(self, H = lambda _: ''):
        self.H = H


    def digest(self, D):
        # The hash corresponding to a node is the Hash function applied
        # to the concatenation its children's hashes and its own value
        if not D: return ''
        c, _, (k, dL, dR), _ = D
        return self.H((c, k, dL, dR))


    def search(self, q, D):
        """
        Search through the binary tree.

        Returns:
            an array containing the values at each node visited
        """
        result = []
        while D:
            c, L, (k, dL, dR), R = D
            result.append((c, (k, dL, dR)))
            D = L if q <= k else R
        return tuple(result)


    def query(self, q, D):
        proof = self.search(q, D)
        if not proof: return None, proof
        (c,(k, _, _)) = proof[-1]
        return k if k == q else None, proof


    def reconstruct(self, proof):
        """
        Reconstruct a partial view of a tree (a path from root to leaf)
        given a proof object consisting of the colors and values from
        the path.

        Correctness invariant:
            forall q and D:
                 R = reconstruct(search(q, D))
                 assert digest(D) == digest(R)
                 assert search(q, D) == search(q, R)
                 assert digest(insert(q, D)) == digest(insert(q, R))
        """
        proof = iter(proof)
        try:
            (c, (k, dL, dR)) = proof.next()
        except StopIteration:
            return ()

        child = self.reconstruct(proof)
        if not child:
            assert dL == dR == ''
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
        balance, rehash = self.balance, self.rehash
        x = (q, '', '')

        def ins(D):
            # Trivial case
            if not D: return ('B', (), x, ())

            # Element already exists (insert is idempotent)
            c, a, y, b = D
            assert q != y[0]

            # Leaf node found (this will become the parent)
            if q < y[0] and not a:
                return balance(rehash(('R', ins(a), x, make_black(D))))

            if q > y[0] and not b: 
                return balance(rehash(('R', make_black(D), y, ins(b))))

            # Otherwise recurse
            if q < y[0]: return balance((c, ins(a), y, b))
            if q > y[0]: return balance((c, a, y, ins(b)))

        make_black = lambda (c,a,y,b): ('B',a,y,b)
        return rehash(make_black(ins(D)))


    def delete(self, q, D):
        """
        """
        raise NotImplemented


    def balance(self, D):
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

        return self.rehash(match(B,(R,(R,a,(x,m,n),b),(y,_,o),c),(z,_,p),d) or
                           match(B,(R,a,(x,m,_),(R,b,(y,n,o),c)),(z,_,p),d) or
                           match(B,a,(x,m,_),(R,(R,b,(y,n,o),c),(z,_,p),d)) or
                           match(B,a,(x,m,_),(R,b,(y,n,_),(R,c,(z,o,p),d))) or
                           D)


    def rehash(self, D):
        # Recompute the hashes for each node, but only if the children
        # are available. Otherwise, we assume the current value is correct.
        c, L, (k, dL, dR), R = D
        if L: dL = self.digest(L)
        if R: dR = self.digest(R)
        return (c, L, (k, dL, dR), R)
