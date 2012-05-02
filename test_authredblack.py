import unittest
import random
from Crypto.Hash import SHA256
import json
import authredblack; reload(authredblack)
from authredblack import AuthRedBlack


def invariants(D):
    # The following invariants hold at all times for the red-black search tree

    # Our definition of a search tree: each inner node contains the largest
    # value in its left subtree.
    def _greatest(D):
        if not D: return
        (c, a, y, b) = D
        if a and b:
            if isinstance(y, tuple): assert _greatest(a)[0] == y[0] 
            else: assert _greatest(a) == y
            return _greatest(b)
        else:
            assert not a and not b
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
        if not a and not b: 
            assert c == 'B'
            return 1
        p = _paths_black(a)
        assert p == _paths_black(b)
        return p + (c == 'B')

    # Merkle tree digests must be computed correctly
    def _digests(D):
        if not D: return
        (c, a, (x, dL, dR), b) = D
        if a: assert dL == digest(a)
        else: assert not dL
        if b: 
            if dR != digest(b): print dR, digest(b)
            assert dR == digest(b)
        else: assert not dR
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
        global digest, search, insert, reconstruct, balance, verify, query
        ARB = AuthRedBlack()
        digest = ARB['digest']
        search = ARB['search']
        insert = ARB['insert']
        reconstruct = ARB['reconstruct']
        balance = ARB['balance']
        verify = ARB['verify']
        query = ARB['query']

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
                assert query(i, D)[0] == (i in ref)
                assert verify(i, d0, search(i, D))

    def test_insert_reconstruct_search(self):
        T = ()
        for i in range(0, 8, 2): T = insert(i, T)
        for i in (-1,1,3,5,7):
            R = reconstruct(iter(search(i, T)))
            invariants(T)
        assert (search(i, insert(i, T)) == 
                search(i, insert(i, R)))


class AuthRedBlackTest(unittest.TestCase):
    def setUp(self):
        global digest, search, insert, reconstruct, balance, verify
        H = lambda (c, k, dL, dR): SHA256.new(json.dumps((c,k,dL,dR))).hexdigest()
        ARB = AuthRedBlack(H)
        digest = ARB['digest']
        search = ARB['search']
        insert = ARB['insert']
        reconstruct = ARB['reconstruct']
        balance = ARB['balance']
        verify = ARB['verify']
        query = ARB['query']

    def test_auth(self):
        T = ()
        for i in range(0,10,3): T = insert(i, T)
        for i in range(1,11,3): T = insert(i, T)
        for i in range(2,12,3):
            s = search(i, T)
            r = reconstruct(iter(s))
            invariants(T)
            assert search(i, r) == search(i, T)
            assert search(i, insert(i, r)) == search(i, insert(i, T))
            assert digest(insert(i, r)) == digest(insert(i, T))



if __name__ == '__main__':
    unittest.main()

    ARB = AuthRedBlack()
    digest = ARB['digest']
    search = ARB['search']
    insert = ARB['insert']
    reconstruct = ARB['reconstruct']
    balance = ARB['balance']
    verify = ARB['verify']
    query = ARB['query']
