import unittest; reload(unittest)
import random
from Crypto.Hash import SHA256
import json
import redblack; reload(redblack)
from redblack import RedBlack, MerkleRedBlack
from redblack import RecordTraversal, ReplayTraversal
from redblack import RedBlackZipper, RedBlackMixin

def invariants(D, leftleaning=False):
    # The following invariants hold at all times for the red-black search tree

    # Our definition of a search tree: each inner node contains the largest
    # value in its left subtree.
    def _greatest(D):
        if not D: return
        (c, L, (k,v), R) = D
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
    def _noredchild(D, right=False):
        if not D: return
        (c, L, _, R) = D
        assert not (right and c=='R')
        _noredchild(L)
        _noredchild(R, True)

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

    _greatest(D)
    _redparent(D)
    _paths_black(D)
    if leftleaning: _noredchild(D)

def inorder_traversal(RB, D):
    inorder = []
    def _set(D):
        if not D: return
        (_, L, k, R) = D
        if RB.empty(L) and RB.empty(R): inorder.append(k)
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
            invariants(D)
            assert v == search(v, D)[0]

        random.shuffle(values)
        for v in values[1:]:
            D = delete(v, D)
            invariants(D)
            assert v != search(v, D)[0]

    def test_degenerate(self):
        search = self.RB.search
        insert = self.RB.insert
        dO = self.RB.E
        assert insert('a', ()) == ('B', dO, ('a',''), dO)
        self.assertRaises(ValueError, search, '', ())

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
                invariants(D)
                ref.remove((i,chr(i)))
                assert inorder_traversal(self.RB, D) == sorted(ref)


class MerkleRedBlackTest(unittest.TestCase):
    def setUp(self):
        self.RB = MerkleRedBlack()

    def test_traversal_insert(self):
        RB = self.RB
        D = RB.E
        H = RB.H
        d0 = D[0]
        values = range(32)
        random.shuffle(values)
        for v in values:
            T = RecordTraversal(H)
            D = T.insert(v,D)
            #invariants(D)
            R = ReplayTraversal(T.VO, H)
            assert R.insert(v, d0) == D[0]
            d0 = D[0]
            
    def test_traversal_delete(self):
        RB = self.RB
        D = RB.E
        H = RB.H
        values = range(32)
        random.shuffle(values)
        for v in values:
            D = RecordTraversal(H).insert(v, D)

        d0 = D[0]
        random.shuffle(values)
        for v in values:
            T = RecordTraversal(H)
            D = T.delete(v, D)
            #invariants(D)
            R = ReplayTraversal(T.VO, H)
            assert R.delete(v, d0) == D[0]
            d0 = D[0]

if __name__ == '__main__':
    #unittest.main()
    pass

class MyRedBlack(RedBlackZipper, RedBlackMixin):
    def __repr__(self): return str(list(self.preorder_traversal()))

def inorder(d): return [x[1][0] for x in d.inorder_traversal() if x[1][1] != ()]

d = MyRedBlack()
d.clear()
vs = range(100)
random.shuffle(vs)
for i in vs:
    print 'insert', i
    d.insert(i)
    invariants(d._focus, leftleaning=True)
assert(inorder(d) == sorted(vs))

def random_insert(n):
    vs = range(n)
    random.shuffle(vs)
    d = MyRedBlack()
    for v in vs: d.insert(v)

def random_insert_rb(n):
    vs = range(n)
    random.shuffle(vs)
    RB = RedBlack()
    D = RB.E
    for v in vs: D = RB.insert(v, D)
