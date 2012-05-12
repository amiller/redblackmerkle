import unittest; reload(unittest)
import random
from Crypto.Hash import SHA256
import json
import redblack; reload(redblack)
from redblack import RedBlack


def invariants(D):
    # The following invariants hold at all times for the red-black search tree

    # Our definition of a search tree: each inner node contains the largest
    # value in its left subtree.
    def _greatest(D):
        if not D: return
        (c, L, (k, _, _), R) = D
        assert bool(L) == bool(R)
        if L and R:
            assert _greatest(L) == k
            return _greatest(R)
        else: return k

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
        global reconstruct, digest, insert, search, delete, size
        RB = RedBlack()
        reconstruct = RB.reconstruct
        digest = RB.digest
        insert = RB.insert
        search = RB.search
        delete = RB.delete
        size = RB.size

    def test_degenerate(self):
        dO = digest(())
        assert insert('a', ()) == (('B', (), ('a', dO, dO), ()), ())
        self.assertRaises(ValueError, search, 'notfound', ())
        assert digest(()) == (0,hash(()))

    def _test_reconstruct(self, D, n):
        for q in range(n):
            R = reconstruct(digest(D), search(q, D)[1])
            assert search(q, R) == search(q, D)

    def test_sequential(self):
        D = ()
        for i in range(10):
            D, _ = insert(i, D)
            assert size(D) == i+1
            self._test_reconstruct(D, 10)
            invariants(D)

    def test_random(self, n=100):
        D = ()
        ref = set()
        for _ in range(n):
            i = random.randint(0,n)
            if not i in ref:
                D, _ = insert(i, D)
                ref.add(i)
            invariants(D)
            d0 = digest(D)
            for i in range(n):
                assert (search(i, D)[0] == i) == (i in ref)

    def test_delete_random(self, n=300):
        for _ in range(n):
            D = ()
            values = range(11)
            random.shuffle(values)
            for i in values: D, _ = insert(i, D)
            random.shuffle(values)
            for i in values:
                S, VO = delete(i, D)
                R = reconstruct(digest(D), VO)
                SR, _VO = delete(i, R)
                assert _VO == VO
                if S:
                    assert search(i, S)[0] != i
                    assert digest(SR) == digest(S)
                invariants(S)
                D = S

    def test_insert_search(self):
        D = ()
        for i in range(0, 8, 2): D, _ = insert(i, D)
        for i in (-1,1,3,5,7):
            R = reconstruct(digest(D), search(i, D)[1])
            invariants(D)
            S, VO = insert(i, D)
            SR, _VO = insert(i, R)
            assert digest(S) == digest(SR)
            assert _VO == VO


class AuthSelectRedBlackTest(unittest.TestCase):
    def setUp(self):
        global reconstruct, digest, insert, search, select, rank
        H = lambda x: '' if not x else SHA256.new(json.dumps(x)).hexdigest()
        RB = RedBlack(H)
        reconstruct = RB.reconstruct
        digest = RB.digest
        insert = RB.insert
        select = RB.select
        search = RB.search
        rank = RB.rank

    def test_auth(self):
        N = 100
        D = ()
        values = range(N)
        random.shuffle(values)
        for i in values[:-10]: D, _ = insert(i, D)
        for i in values[-10:]:
            S, VO = insert(i, D)
            R = reconstruct(digest(D), VO)
            assert search(i, R) == search(i, D)
            SR, _VO = insert(i, R)
            assert _VO == VO
            assert search(i, SR) == search(i, S)
            assert digest(SR) == digest(S)

    def test_select(self):
        N = 100
        D = ()
        values = range(N)
        random.shuffle(values)
        for v in values: D, _ = insert(v, D)
        d0 = digest(D)

        for _ in range(100):
            i = random.randint(0,N-1)
            v = select(i, D)
            assert i == rank(v, D)
            _, VO = search(v, D)
            R = reconstruct(d0, VO)
            assert i == rank(v, R)
            assert v == select(i, R)


if __name__ == '__main__':
    unittest.main()

