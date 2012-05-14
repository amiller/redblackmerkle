import unittest; reload(unittest)
import random
from Crypto.Hash import SHA256
import json
import redblack; reload(redblack)
from redblack import RedBlack
from redblack import SelectRedBlack
from redblack import WeightSelectRedBlack
import persistent; reload(persistent)
from persistent import PersistentAuthDict

def invariants(RB, D):
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
        if L: assert dL == RB.digest(L)
        if R: assert dR == RB.digest(R)
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
        self.RB = RedBlack()

    def test_degenerate(self):
        digest = self.RB.digest
        search = self.RB.search
        insert = self.RB.insert
        dO = digest(())
        assert insert('a', ()) == (('B', (), ('a', dO, dO), ()), ())
        self.assertRaises(ValueError, search, '', ())
        assert digest(()) == hash(())

    def _test_reconstruct(self, D, n):
        search = self.RB.search
        reconstruct = self.RB.reconstruct
        digest = self.RB.digest
        for q in range(n):
            R = reconstruct(digest(D), search(q, D)[1])
            assert search(q, R) == search(q, D)

    def test_random(self, n=100):
        insert = self.RB.insert
        digest = self.RB.digest
        search = self.RB.search
        D = ()
        ref = set()
        for _ in range(n):
            i = random.randint(0,n)
            if not i in ref:
                D, _ = insert(i, D)
                ref.add(i)
            invariants(self.RB, D)
            d0 = digest(D)
            for i in range(n):
                assert (search(i, D)[0] == i) == (i in ref)

    def test_delete_random(self, n=300):
        reconstruct = self.RB.reconstruct
        insert = self.RB.insert
        search = self.RB.search
        digest = self.RB.digest
        delete = self.RB.delete
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
                invariants(self.RB, S)
                D = S

    def test_insert_search(self):
        reconstruct = self.RB.reconstruct
        insert = self.RB.insert
        search = self.RB.search
        digest = self.RB.digest
        D = ()
        for i in range(0, 8, 2): D, _ = insert(i, D)
        for i in (-1,1,3,5,7):
            R = reconstruct(digest(D), search(i, D)[1])
            invariants(self.RB, D)
            S, VO = insert(i, D)
            SR, _VO = insert(i, R)
            assert digest(S) == digest(SR)
            assert _VO == VO

    def test_auth(self):
        reconstruct = self.RB.reconstruct
        insert = self.RB.insert
        search = self.RB.search
        digest = self.RB.digest
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



class SelectRedBlackTest(unittest.TestCase):
    def setUp(self):
        H = lambda x: '' if not x else SHA256.new(json.dumps(x)).hexdigest()
        self.RB = SelectRedBlack(H)

    def test_sequential(self):
        insert = self.RB.insert
        size = self.RB.size
        D = ()
        for i in range(10):
            D, _ = insert(i, D)
            assert size(D) == i+1
            invariants(self.RB, D)

    def test_select(self):
        reconstruct = self.RB.reconstruct
        insert = self.RB.insert
        search = self.RB.search
        digest = self.RB.digest
        select = self.RB.select
        rank = self.RB.rank
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


class WeightSelectRedBlackTest(unittest.TestCase):
    def setUp(self):
        H = lambda x: '' if not x else SHA256.new(json.dumps(x)).hexdigest()
        self.RB = WeightSelectRedBlack(H)

    def test_weight(self):
        insert = self.RB.insert
        digest = self.RB.digest
        select_weight = self.RB.select_weight
        within_eps = lambda a,b: abs(a-b) < 1e-5
        D = ()
        N = 100
        weights = [random.randint(0,100) for _ in range(N)]
        weights = [w / float(sum(weights)) for w in weights]
        assert within_eps(sum(weights), 1)
        total = 0.
        for i,w in enumerate(weights):
            total += w
            D,_ = insert((i,w), D)
            (_, (W, _)) = digest(D)
            assert within_eps(W, total)

        cumpdf = [sum(weights[:i]) for i in range(N)]
        for r in [random.random() for _ in range(20)]:
            (i,w), residue = select_weight(r, D)
            assert cumpdf[i] <= r
            assert within_eps(cumpdf[i] + residue, r)
            assert i == N-1 or cumpdf[i+1] > r


class PersistentAuthDictTest(unittest.TestCase):
    def setUp(self):
        H = lambda x: '' if not x else SHA256.new(json.dumps(x)).hexdigest()[:8]
        self.PAD = PersistentAuthDict(SelectRedBlack(H))

    def test_pad(self):
        insert = self.PAD.insert
        digest = self.PAD.digest
        search = self.PAD.search
        reconstruct = self.PAD.reconstruct

        PAD = (), {}

        values = range(20)
        random.shuffle(values)

        for v in values:
            d0 = digest(PAD)
            (N,_) = d0
            S, VO = insert(v, PAD)
            if N:
                R = reconstruct(d0, VO)
                assert digest(R) == digest(PAD)
                assert search(v, PAD) == search(v, R)
            PAD = S

        for i, v in enumerate(values):
            if i < 1: continue
            # Each element should be in the most recent set, but
            # not in the one before that
            assert search(v, PAD, t=i)[0] == v
            assert search(v, PAD, t=i-1)[0] != v



if __name__ == '__main__':
    unittest.main()
