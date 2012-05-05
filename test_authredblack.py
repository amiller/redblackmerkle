import unittest
import random
from Crypto.Hash import SHA256
import json
import authredblack; reload(authredblack)
from authredblack import RedBlack, AuthSelectRedBlack


def invariants(D):
    # The following invariants hold at all times for the red-black search tree

    # Our definition of a search tree: each inner node contains the largest
    # value in its left subtree.
    def _greatest(D):
        if not D: return
        (c, a, y, b) = D
        if a and b:
            if isinstance(y, tuple): assert _greatest(a)[0] < y[0] 
            else: assert _greatest(a) < y
            return _greatest(b)
        else:
            #assert not a and not b
            return y

    # No red node has a red parent
    def _redparent(D, parent_is_red=False):
        if not D: return
        (c, a, y, b) = D
        assert not (parent_is_red and c == 'R')
        _redparent(a, c == 'R')
        _redparent(b, c == 'R')

    # Paths are balanced if the number of black nodes along any simple path
    # from this root to a leaf are the same
    def _paths_black(D):
        if not D: return 0
        (c, a, y, b) = D
        p = _paths_black(a)
        assert p == _paths_black(b)
        return p + (c == 'B')

    # Merkle tree digests must be computed correctly
    def _digests(D):
        if not D: return
        (c, a, (x, dL, dR), b) = D
        if a: assert dL == digest(a)
        if b: assert dR == digest(b)
        _digests(a)
        _digests(b)

    _greatest(D)
    _redparent(D)
    _paths_black(D)
    _digests(D)


def test_cases():
    global correct_result, test_case_W, test_case_N, test_case_S, test_case_E
    R,B = 'RB'
    x,y,z = ((k, '', '') for k in 'xyz')
    a,b,c,d = ((B,(),(k, '', ''),()) for k in 'abcd')

    # Test cases from figure 1 in
    # http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps
    test_case_W = (B,(R,(R,a,x,b),y,c),z,d)
    test_case_N = (B,(R,a,x,(R,b,y,c)),z,d)
    test_case_S = (B,a,x,(R,(R,b,y,c),z,d))
    test_case_E = (B,a,x,(R,b,y,(R,c,z,d)))
    correct_result = (R,(B,a,x,b),y,(B,c,z,d))
test_cases()

class RedBlackTest(unittest.TestCase):
    """
    The tree.insert, search, 
    """
    def setUp(self):
        global digest, search, insert, reconstruct, balance, query
        RB = RedBlack()
        digest = RB.digest
        search = RB.search
        insert = RB.insert
        reconstruct = RB.reconstruct
        balance = RB.balance
        query = RB.query

    def test_degenerate(self):
        assert insert('a', ()) == ('B', (), ('a','',''), ())
        assert search(0, ()) == ()
        assert reconstruct(iter(())) == ()
        assert digest(()) == ''

    def test_simple_cases(self):
        assert balance(test_case_W) == correct_result
        assert balance(test_case_N) == correct_result
        assert balance(test_case_S) == correct_result
        assert balance(test_case_E) == correct_result

    def _test_reconstruct(self, D, n):
        for q in range(n):
            found, proof = query(q, D)
            r = reconstruct(iter(proof))
            if found: assert proof == tuple(search(q, r))

    def test_sequential(self):
        D = ()
        for i in range(10):
            D = insert(i, D)
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
                assert (query(i, D)[0] == i) == (i in ref)

    def test_insert_reconstruct_search(self):
        T = ()
        for i in range(0, 8, 2): T = insert(i, T)
        for i in (-1,1,3,5,7):
            R = reconstruct(iter(search(i, T)))
            invariants(T)
        assert (search(i, insert(i, T)) == 
                search(i, insert(i, R)))


class AuthSelectRedBlackTest(unittest.TestCase):
    def setUp(self):
        global digest, search, insert, reconstruct, select, verify, rank
        H = lambda x: '' if not x else SHA256.new(json.dumps(x)).hexdigest()
        ASRB = AuthSelectRedBlack(H)
        digest = ASRB.digest
        search = ASRB.search
        insert = ASRB.insert
        reconstruct = ASRB.reconstruct
        query = ASRB.query
        select = ASRB.select
        rank = ASRB.rank
        verify = ASRB.verify

    def test_auth(self):
        N = 100
        D = ()
        values = range(N)
        random.shuffle(values)
        for i in values[:-10]: D = insert(i, D)
        for i in values[-10:]:
            s = search(i, D)
            r = reconstruct(s)
            invariants(D)
            assert search(i, r) == search(i, D)
            assert search(i, insert(i, r)) == search(i, insert(i, D))
            assert digest(insert(i, r)) == digest(insert(i, D))

    def test_select(self):
        N = 100
        D = ()
        values = range(N)
        random.shuffle(values)
        for v in values: D = insert(v, D)
        d0 = digest(D)

        for _ in range(100):
            i = random.randint(0,N-1)
            v, P = select(i, D)
            assert i == rank(v, D)
            assert verify(d0, v, i, P)




if __name__ == '__main__':
    unittest.main()
