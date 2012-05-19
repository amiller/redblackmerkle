import unittest; reload(unittest)
import random
from Crypto.Hash import SHA256
import json
import redblack; reload(redblack)
from redblack import RedBlack
from redblack import SelectRedBlack
from redblack import WeightSelectRedBlack
from redblack import RecordTraversal, ReplayTraversal


def invariants(RB, D):
    # The following invariants hold at all times for the red-black search tree

    # Our definition of a search tree: each inner node contains the largest
    # value in its left subtree.
    def _greatest(D):
        if not D: return
        (c, L, ((k,v), _, _), R) = D
        assert bool(L) == bool(R)
        if L and R:
            assert v == ()
            assert _greatest(L) == k
            return _greatest(R)
        else:
            if v == (): print D
            assert v != ()
            return k

    # No red node has a red parent
    def _redparent(D, parent_is_red=False):
        if not D: return
        (c, L, _, R) = D
        assert not (parent_is_red and c == 'R')
        _redparent(L, c == 'R')
        _redparent(R, c == 'R')

    # Paths are balanced if the number of black nodes along any simple path
    # from this root to a leaf are the same
    def _paths_black(D):
        if not D: return 0
        (c, L, _, R) = D
        p = _paths_black(L)
        if not p == _paths_black(R):
            print _paths_black(R), _paths_black(L)
            print D
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


def inorder_traversal(RB, D):
    inorder = []
    def _set(D):
        if not D: return
        (_, L, (k, dL, dR), R) = D
        if dL == dR == RB.dO: inorder.append(k)
        _set(L)
        _set(R)
    _set(D)
    return inorder


class RedBlackTest(unittest.TestCase):
    def setUp(self):
        self.RB = RedBlack()

    def test_redblack(self):
        insert = self.RB.insert
        delete = self.RB.delete
        search = self.RB.search
        D = ()
        values = range(32); random.shuffle(values)
        for v in values:
            D = insert(v, D)
            invariants(self.RB, D)
            assert v == search(v, D)[0]

        random.shuffle(values)
        for v in values[1:]:
            D = delete(v, D)
            invariants(self.RB, D)
            assert v != search(v, D)[0]

    def test_traversal_insert(self):
        D = ()
        RB = self.RB
        H = RB.H
        d0 = RB.digest(D)
        values = range(32)
        random.shuffle(values)
        for v in values:
            T = RecordTraversal(H, D)
            d = T.insert(v)
            D = T.reconstruct(d)
            invariants(RB, D)
            R = ReplayTraversal(H, d0, T.VO)
            assert R.insert(v) == d
            d0 = d
            
    def test_traversal_delete(self):
        D = ()
        RB = self.RB
        H = RB.H
        values = range(32)
        random.shuffle(values)
        for v in values:
            T = RecordTraversal(H, D)
            D = T.reconstruct(T.insert(v))

        d0 = RB.digest(D)
        random.shuffle(values)
        for v in values:
            T = RecordTraversal(H, D)
            d = T.delete(v)
            D = T.reconstruct(d)
            invariants(RB, D)
            R = ReplayTraversal(H, d0, T.VO)
            assert R.delete(v) == d
            d0 = d

    def test_degenerate(self):
        digest = self.RB.digest
        search = self.RB.search
        insert = self.RB.insert
        dO = digest(())
        assert insert('a', ()) == ('B', (), (('a',''), dO, dO), ())
        self.assertRaises(ValueError, search, '', ())
        assert digest(()) == hash(())

    def test_insert_random(self, n=100):
        insert = self.RB.insert
        D = ()
        ref = set()
        for _ in range(n):
            i = random.randint(0,n)
            if not (i,chr(i)) in ref:
                D = insert(i, D, v=chr(i))
                ref.add((i,chr(i)))
            assert inorder_traversal(self.RB, D) == sorted(ref)

    def test_delete_random(self, n=100):
        insert = self.RB.insert
        delete = self.RB.delete
        for _ in range(n):
            D = ()
            values = range(15)
            random.shuffle(values)
            for i in values: D = insert(i, D, v=chr(i))

            ref = set((v,chr(v)) for v in values)
            random.shuffle(values)
            for i in values:
                D = delete(i, D)
                invariants(self.RB, D)
                ref.remove((i,chr(i)))
                assert inorder_traversal(self.RB, D) == sorted(ref)


class SelectRedBlackTest(unittest.TestCase):
    def setUp(self):
        H = lambda x: '' if not x else SHA256.new(json.dumps(x)).hexdigest()
        self.RB = SelectRedBlack(H)

    def test_sequential(self):
        insert = self.RB.insert
        size = self.RB.size
        D = ()
        for i in range(10):
            D = insert(i, D)
            assert size(D) == i+1
            invariants(self.RB, D)

    def test_select(self):
        insert = self.RB.insert
        record = self.RB.record
        replay = self.RB.replay
        search = self.RB.search
        digest = self.RB.digest
        select = self.RB.select
        rank = self.RB.rank
        N = 100
        D = ()
        values = range(N)
        random.shuffle(values)
        for v in values: D = insert(v, D)

        for _ in range(100):
            i = random.randint(0,N-1)
            v = select(i, D)
            assert i == rank(v, D)

            T = record(D)
            k = T.search(v)
            assert replay(digest(D), T.VO).rank(v) == i
            assert replay(digest(D), T.VO).select(i) == v


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
            D = insert(i, D, v=(w,))
            (_, (W, _)) = digest(D)
            assert within_eps(W, total)

        cumpdf = [sum(weights[:i]) for i in range(N)]
        for r in [random.random() for _ in range(20)]:
            i, residue = select_weight(r, D)
            assert cumpdf[i] <= r
            assert within_eps(cumpdf[i] + residue, r)
            assert i == N-1 or cumpdf[i+1] > r



if __name__ == '__main__':
    unittest.main()
