import random
from Crypto.Hash import SHA256
import json
import redblack; reload(redblack)
from redblack import RedBlack
import unittest


def invariants(D):
    # The following invariants hold at all times for the red-black search tree

    # Our definition of a search tree: each inner node contains the largest
    # value in its left subtree.
    def _greatest(D):
        if not D: return
        (c, L, (k, _, _), R) = D
        if L and R:
            assert _greatest(L) == k
            return _greatest(R)
        else:
            assert not L and not R
            return k

    # No red node has a red parent
    def _redparent(D, parent_is_red=False):
        if not D: return
        (c, L, (k, _, _), R) = D
        assert not (parent_is_red and c == 'R')
        _redparent(L, c == 'R')
        _redparent(R, c == 'R')

    # Paths are balanced if the number of black nodes along any simple path
    # from this root to a leaf are the same
    def _paths_black(D):
        if not D: return 0
        (c, L, y, R) = D
        p = _paths_black(L)
        assert p == _paths_black(R)
        return p + (c == 'B')

    # Merkle tree digests must be computed correctly
    def _digests(D):
        if not D: return
        (c, L, (k, dL, dR), R) = D
        if L: assert dL == digest(L)
        if R: assert dR == digest(R)
        _digests(L)
        _digests(R)

    _greatest(D)
    _redparent(D)
    _paths_black(D)
    _digests(D)


class RedBlackTest(unittest.TestCase):
    """
    The tree.insert, search, 
    """
    def setUp(self):
        global digest, search, insert, verify, balance, query, size
        RB = RedBlack()
        balance = RB.balance
        digest = RB.digest
        search = RB.search
        insert = RB.insert
        query = RB.query
        size = RB.size

    def test_degenerate(self):
        assert insert('a', ()) == ('B', (), ('a',(0,''),(0,'')), ())
        assert search('notfound', ()) == ()
        assert digest(()) == (0,'')

    def _test_reconstruct(self, D, n):
        for q in range(n):
            R = search(q, D)
            assert query(q, R) == query(q, D)

    def test_sequential(self):
        D = ()
        for i in range(10):
            D = insert(i, D)
            assert size(D) == i+1
            self._test_reconstruct(D, 10)
            invariants(D)

    def test_random(self, n=100):
        D = ()
        ref = set()
        for _ in range(n):
            i = random.randint(0,n)
            if not i in ref:
                D = insert(i, D)
                ref.add(i)
            invariants(D)
            d0 = digest(D)
            for i in range(n):
                assert (query(i, D) == i) == (i in ref)

    def test_insert_search(self):
        T = ()
        for i in range(0, 8, 2): T = insert(i, T)
        for i in (-1,1,3,5,7):
            R = search(i, T)
            invariants(T)
            assert (search(i, insert(i, T)) == 
                    search(i, insert(i, R)))


class AuthSelectRedBlackTest(unittest.TestCase):
    def setUp(self):
        global digest, search, insert, select, verify, rank
        H = lambda x: '' if not x else SHA256.new(json.dumps(x)).hexdigest()
        RB = RedBlack(H)
        digest = RB.digest
        search = RB.search
        insert = RB.insert
        select = RB.select
        verify = RB.verify
        query = RB.query
        rank = RB.rank

    def test_auth(self):
        N = 100
        D = ()
        values = range(N)
        random.shuffle(values)
        for i in values[:-10]: D = insert(i, D)
        for i in values[-10:]:
            R = search(i, D)
            assert verify(digest(D), R)
            invariants(D)
            assert search(i, R) == search(i, D)
            assert search(i, insert(i, R)) == search(i, insert(i, D))
            assert digest(insert(i, R)) == digest(insert(i, D))

    def test_select(self):
        N = 100
        D = ()
        values = range(N)
        random.shuffle(values)
        for v in values: D = insert(v, D)
        d0 = digest(D)

        for _ in range(100):
            i = random.randint(0,N-1)
            v = select(i, D)
            R = search(v, D)
            assert i == rank(v, D)
            assert verify(d0, R)
            assert i == rank(v, R)
            assert v == select(i, R)


if __name__ == '__main__':
    unittest.main()
