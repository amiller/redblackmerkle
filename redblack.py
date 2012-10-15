
"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012

This RedBlack tree is an Authenticated Set [1], based on a balanced
binary search tree. The tree is strictly balanced, so that all usual
operations can be performed in O(log N) worst-case time. The tree is augmented
with secure hashes for each node, forming a Merkle tree. This allows each 
operation to be 'replayed' by a Verifier using only O(log N) data. Only O(1) of
'trusted' state (the Merkle tree root hash) must be maintained by the Verifier.

Additionally, this tree supports selection of an element by its rank, which is
especially useful in choosing elements at random for a Proof-of-Throughput.

This implementation uses a combination of Okasaki style balancing for 
insert [2] and Kazu Yamamato's version of delete [3,4,5].


[1] Persistent Authenticated Dictionaries and Their Applications
    Agnostopolous, Goodrich, and Tamassia.
    http://cs.brown.edu/people/aris/pubs/pad.pdf

[2] Purely Functional Data Structures
    Chris Okasaki
    http://www.eecs.usma.edu/webs/people/okasaki/jfp99.ps

[3] Missing method: How to delete from Okasaki's red-black trees
    Matt Might
    http://matt.might.net/articles/red-black-delete/

[4] Efficient Verified Red-Black Trees
    Andrew Appel
    http://www.cs.princeton.edu/~appel/papers/redblack.pdf

[5] Purely Functional Left-Leaning Red-Black Trees
    Kazu Yamamoto
    http://www.mew.org/~kazu/proj/red-black-tree/


Type definitions and common notations:
======================================

RedBlack():
    A RedBlack tree that can be augmented with a 'digest' field, which is
    assumed to contain at least a collision-resistant hash function. The
    digests for the subtrees are stored along with each node. The digests
    are recomputed as necessary during insert and delete in order to maintain
    consistency.

 ** Note that RedBlack objects simply define functions, the actual data 
    structure D is just a tuple, as described below

D:
    A Node in the tree, especially the root. Of the form:
        (Color, Left, (Element, LeftDigest, RightDigest), Right) = D

    - Typically abbreviated
        (c, L, (k, dL, dR), R) = D

    - c in ('R', 'B'): red and black labels for balancing
        L, R: the children, also Nodes,
        dL, dR: digests of the children
        k: each non-leaf's value is equal to the largest leaf value in the left
           sub-tree

    - () represents the empty tree.
    - dO == digest(()) is the empty-digest

    - The following operations are defined as you'd expect:

        D = insert(q, D)   # unless q is already in the set
        D = delete(q, D)   # unless the set does not contain q
        v = search(q, D)   # Returns the smallest element >= q, unless q is the
                           # largest element in the tree

VO:
    Each of the tree operations is defined in terms of a stateful 'Traversal'
    object, which runs in one of two modes:

    Record: 
        The data for every node visited during subsequent operations on T
        is appended to a Verification Object (VO).

        T = record(D)
        d0 = T.insert(q)
        VO = T.VO

    Replay: 
        A VO created from a recording can be replayed, simulating the
        operation on the full tree.

        T = replay(d0, VO)
        d0 = T.insert(q)

 ** Security Claim **

    If an operation on a Replay traversal returns a value, then it is the same
    value that would be returned by the operation on the original tree.

    Proof sketch:
       At each step during a traversal, the digest for each node is known
       before the node's data is accessed. During a Replay, the digest is
       is recomputed and verified.

 ** Bounded Cost-of-Verification Claim **

    The tree is balanced such that the longest possible path from the root to
    a leaf is 2 log N. The worst-case bounds for all operations are given
    below:
          delete: 4 + 3 log N
          insert: 2 log N
          search: 2 log N

    TODO: I think these are wrong! How to construct the worst case?
"""

class DuplicateElementError(ValueError):
    pass

from itertools import izip
import collections
from functools import partial

class peekable:
    """An iterator that supports a peek operation.
    """
    def __init__(self, iterable):
        self._iterable = iter(iterable)
        self._cache = collections.deque()
        
    def __iter__(self):
        return self

    def _fillcache(self, n):
        while len(self._cache) < n:
            self._cache.append(self._iterable.next())
    
    def next(self, n=None):
        self._fillcache(n is None and 1 or n)
        if n is None:
            result = self._cache.popleft()
        else:
            result = [self._cache.popleft() for i in range(n)]
        return result

    def peek(self, n=None):
        self._fillcache(n is None and 1 or n)
        if n is None:
            result = self._cache[0]
        else:
            result = [self._cache[i] for i in range(n)]
        return result

class RedBlackZipper(object):

    def __init__(self, D=()):
        self._path = []
        self._stack = []
        self._focus = D
        self.E = ()

    # Focus on one of the children
    def down(self, LR):
        """
        args: 'L' or 'R'
        precondition: current focus is not empty
        effect: pushes the current focus on the stack, moves focus to child
        returns: () if node is empty
        """
        assert LR in ('L','R')
        assert not self.empty()
        self._path.append((LR, self._focus))
        if LR == 'L': self._focus = self._focus[1]
        if LR == 'R': self._focus = self._focus[3]

    def left(self):
        self._path.append(('L', self._focus))
        self._focus = self._focus[1]

    def right(self):
        self._path.append(('R', self._focus))
        self._focus = self._focus[3]

    # Focus on the parent
    def up(self):
        (LR, (c, L, k, R)) = self._path.pop()
        if LR == 'L': self._focus = (c, self._focus, k, R)
        elif LR == 'R': self._focus = (c, L, k, self._focus)
        else: raise ValueError

    def empty(self): return self._focus == self.E
    def color(self): return self._focus[0]
    def isRed(self): return self._focus != self.E and self._focus[0] == 'R'

    def visit(self):
        assert not self.empty()
        return self._focus[0], self._focus[2]

    # Modify the current focus
    def clear(self): self._focus = self.E
    def leaf(self, c, k): self._focus = (c, self.E, k, self.E)
    def modify(self, c, k): self._focus = (c, self._focus[1], k, self._focus[3])

    # Use a stack to rearrange nodes
    def push(self):
        self._stack.append(self._focus)
        self.clear()
    def pop(self): 
        self.clear()
        self._focus = self._stack.pop()
    def swap(self):
        a = self._stack.pop()
        b = self._stack.pop()
        self._stack.append(a)
        self._stack.append(b)

class RedBlackMixin():

    def colorFlip(self):
        # Flips the colors of the focus and both children
        #print 'colorflip'
        def flip(): self.setColor('R' if self.color() == 'B' else 'B')
        self.left(); flip(); self.up();
        self.right(); flip(); self.up()
        flip()

    def rotate(self, left, right):
        up, push, pop = self.up, self.push, self.pop
        color, setColor = self.color, self.setColor

        # rotateRight (for rotateLeft, swap left/right)
        #    A            B 
        #  B   z   ==>  x   A
        # x y              y z

        left(); right(); push();              # y
        up(); push();                         # B
        up(); c = color(); push();            # A
        self.swap();
        pop(); setColor(c);                   # B
        right(); pop(); setColor('R')         # A
        left(); pop();                        # y
        up(); up();

    def rotateRight(self): self.rotate(self.left, self.right)
    def rotateLeft(self): self.rotate(self.right, self.left)
    def isRed(self): return not self.empty() and self.visit()[0] == 'R'
    def setColor(self, c): _, kv = self.visit(); self.modify(c, kv)
    def color(self): return self.visit()[0]
    def key(self): return self.visit()[1][0]
    def setKey(self, k): c, (_, v) = self.visit(); self.modify(c, (k,v))
    def left(self): self.down('L')
    def right(self): self.down('R')

    def inChild(self, down, f):
        down()
        try: return f()
        finally: self.up()

    def inLeft(self, f): return self.inChild(self.left, f)
    def inRight(self, f): return self.inChild(self.right, f)

    def fixUp(self):
        if self.inRight(self.isRed): 
            self.rotateLeft()
        if self.inLeft(lambda: self.isRed() and self.inLeft(self.isRed)):
            self.rotateRight()
        if self.inLeft(self.isRed) and self.inRight(self.isRed): 
            self.colorFlip()

    def moveRedRight(self):
        self.colorFlip()
        if self.inLeft(lambda: self.inLeft(self.isRed)):
            self.rotateRight()
            self.colorFlip()

    def moveRedLeft(self):
        self.colorFlip()
        if self.inRight(lambda: self.inLeft(self.isRed)):
            self.inRight(self.rotateRight)
            self.rotateLeft()
            self.colorFlip()

    def delete_min(self):
        self._del_min()
        if not self.empty(): self.setColor('B')

    def _del_min(self):
        isRed, empty, leaf = self.isRed, self.empty, self.leaf
        inLeft, inRight = self.inLeft, self.inRight
        push, pop, clear = self.push, self.pop, self.clear

        if inLeft(empty) and inRight(empty):
            clear()
            return True, None

        if inLeft(lambda: not isRed() and not inLeft(isRed)):
            self.moveRedLeft()

        (d, m) = inLeft(self._del_min)
        if d: 
            inRight(push); pop(); self.setColor('B')

        self.fixUp()
        return False, None

    def delete(self, q):
        self._del(q)
        if not self.empty(): self.setColor('B')

    def _del(self, q):
        """
        effect: q no longer exists in the tree in focus
        returns:
            (d,m) = (bool, int) 
              where
                d: True if a leaf was deleted (the focus is now empty)
                m: The maximum element underneath the current focus, if it
                   has changed (or None otherwise)
        """
        
        isRed, empty, leaf = self.isRed, self.empty, self.leaf
        inLeft, inRight = self.inLeft, self.inRight
        push, pop, clear = self.push, self.pop, self.clear

        if empty(): clear(); return False, None

        kk = self.key()
        if inLeft(empty) and inRight(empty):
            assert kk == q, 'Element must exist to be deleted'
            clear()
            return True, None

        newmax = None
        if q <= kk:
            if inLeft(lambda: not isRed() and not inLeft(isRed)):
                 self.moveRedLeft()
            (d, m) = inLeft(partial(self._del,q))
            if d: 
                inRight(push); pop(); self.setColor('B')
            elif q == kk and m is not None:
                self.setKey(m)

        else: # q > kk
            if inLeft(isRed): self.rotateRight()
            if inRight(lambda: not isRed() and not inLeft(isRed)):
                self.moveRedRight()
            (d, newmax) = inRight(partial(self._del,q))
            if d:
                inLeft(push); pop(); self.setColor('B')
                newmax = self.key()

        self.fixUp()
        return False, newmax

    def insert(self, q, v=''):
        self._ins(q, v)
        self.setColor('B')

    def _ins(self, q, v):
        isRed, empty, leaf = self.isRed, self.empty, self.leaf
        inLeft, inRight = self.inLeft, self.inRight
        push, pop = self.push, self.pop

        if empty(): return leaf('B', (q,v))

        _, k = self.visit(); kk = k[0]
        if q == k[0]: raise DuplicateElementError()

        elif q < kk and inLeft(empty):            
            push(); leaf('R', (q,()));
            inRight(pop);
            inLeft(lambda: self._ins(q,v));

        elif q > kk and inRight(empty):
            push(); leaf('R', (kk,()));
            inLeft(pop);
            inRight(lambda: self._ins(q, v));
            
        elif q < kk: inLeft(lambda: self._ins(q, v))
        elif q > kk: inRight(lambda: self._ins(q, v))

        self.fixUp();

    def inorder_traversal(self, emit=None):
        if emit is None: out = []; self.inorder_traversal(out.append); return out
        if self.empty(): return
        self.inLeft(lambda: self.inorder_traversal(emit))
        emit(self.visit())
        self.inRight(lambda: self.inorder_traversal(emit))

    def preorder_traversal(self):
        if self.empty(): raise StopIteration
        yield self.visit()
        self.left()
        for item in self.preorder_traversal(): yield item
        self.up()
        self.right()
        for item in self.preorder_traversal(): yield item
        self.up()

    def from_preorder(self, trav, bound=None):
        trav = peekable(trav)
        assert self.empty()
        try:
            c, k = trav.next()
            self.leaf(c, k)

            _, _k = trav.peek()
            if _k[0] <= k[0]:
                self.left()
                self.from_preorder(trav, k)
                self.up()
                _, _k = trav.peek()

            if bound is None or _k[0] <= bound:
                self.right()
                self.from_preorder(trav, bound)
                self.up()

        except StopIteration: return



class RedBlack(object):
    def __init__(self, E=()):
        """
        Args:
            E: the empty tree
        """
        self.E = E
        # TODO: each of the balance operations sometimes produces more 
        # 'proof' than is necessary. For example, if bL2 is a match,
        # then a 'negative proof' for bL1 is unnecessary. Is there a way
        # to resolve this using the same coroutine setup I have?
        R,B,a,b,c,d,x,y,z = 'RBabcdxyz'
        self.bL1 = (B,(R,(R,a,x,b),y,c),z,d), (R,(B,a,x,b),y,(B,c,z,d))
        self.bL2 = (B,(R,a,x,(R,b,y,c)),z,d), (R,(B,a,x,b),y,(B,c,z,d))
        self.bR1 = (B,a,x,(R,(R,b,y,c),z,d)), (R,(B,a,x,b),y,(B,c,z,d))
        self.bR2 = (B,a,x,(R,b,y,(R,c,z,d))), (R,(B,a,x,b),y,(B,c,z,d))

    """ 
    These are the default "context" functions. They simply pass through
    the node type as the digest type
    """
    def empty(self, D):
        return D == self.E

    def store(self, c, L, k, R):
        return (c, L, k, R)
                                   
    def get(self, D):
        return D


    """
    These are the balancing routines, defined as actions in this context
    """
    def balanceL(self, c, L, k, R):
        D = self.store(c, L, k, R)
        return self.match(self.bL1, D) or self.match(self.bL2, D) or D

    def balanceR(self, c, L, k, R):
        D = self.store(c, L, k, R)
        return self.match(self.bR1, D) or self.match(self.bR2, D) or D

    def unbalancedL(self, c, L, k, R):
        store = self.store
        balanceL = self.balanceL
        red = lambda (_,L,x,R): ('R',L,x,R)
        (_c, _L, _k, _R) = self.get(L)
        if _c == 'B': return balanceL('B',store('R',_L,_k,_R),k,R), c=='B'
        _R = self.get(_R)
        assert c == 'B' and _c == 'R' and _R[0] == 'B'
        return store('B',_L,_k,balanceL('B',store(*red(_R)),k,R)), False

    def unbalancedR(self, c, L, k, R):
        store = self.store
        balanceR = self.balanceR
        red = lambda (_,L,x,R): ('R',L,x,R)
        (_c, _L, _k, _R) = self.get(R)
        if _c == 'B': return balanceR('B',L,k,store('R',_L,_k,_R)), c=='B'
        _L = self.get(_L)
        assert c == 'B' and _c == 'R' and _L[0] == 'B'
        return store('B',balanceR('B',L,k,store(*red(_L))),_k,_R), False

    def match(self, (lhs, rhs), value):
        # Simulates Haskell pattern matching so we can copy the Okasaki
        # balancing rules directly
        table = {}
        get = self.get
        store = self.store

        def _match(left, value):
            if left in ('R','B'): return left == value
            if isinstance(left, tuple):
                return not self.empty(value) and all((_match(*pair) for pair in
                                            izip(left, get(value))))
            table[left] = value
            return True

        def _constr(right, value):
            if right in ('R','B'): return right
            if isinstance(right, tuple):
                return store(*(_constr(*pair) for pair in
                               izip(right, get(value))))
            return table[right]

        return _constr(rhs, value) if _match(lhs, value) else None



    """
    Search, Insert, Delete
    """
    
    def search(self, q, D):
        while True:            
            c, L, k, R = self.get(D)
            if self.empty(L) and self.empty(R): return k
            D = L if q <= k[0] else R

    def insert(self, q, D, v=''):
        balanceL = self.balanceL
        balanceR = self.balanceR
        store = self.store
        get = self.get
        E = self.E
        empty = self.empty

        leaf = store('B', E, (q,v), E)
        if empty(D): return leaf

        def ins(D):
            (c, L, k, R) = get(D)
            node = ('B', L, k, R)
            kk, _ = k

            if q == kk:
                raise DuplicateElementError("Can't insert duplicate element")

            if q < kk and empty(L): return store('R', leaf,  (q,()), store(*node))
            if q > kk and empty(R): return store('R', store(*node), (kk,()), leaf)

            if q < kk: return balanceL(c, ins(L), (kk,()), R)
            if q > kk: return balanceR(c, L, (kk,()), ins(R))
        
        blacken = lambda (_,L,k,R): ('B',L,k,R)
        return store(*blacken(get(ins(D))))


    def delete(self, q, D):
        unbalancedL = self.unbalancedL
        unbalancedR = self.unbalancedR
        store = self.store
        get = self.get
        empty = self.empty
        E = self.E

        def _del(D):
            """
            This function recursively 'bubbles' up three values
            First, the digest of the subtree after deleting the element
            Second, a flag indicating whether we're unbalanced by one
            Third, the maximum value in the subtree, in case the previous 
                   maximum was the deleted element
            """
            if empty(D): return self.E, False, None
            c, L, k, R = get(D)
            if empty(L) and empty(R):
                assert q == k[0]
                return E, True, None
            if q <= k[0]:
                _L, d, m = _del(L)
                if empty(_L): return R, c=='B', None
                if q == k[0]:
                    assert m is not None
                    k = (m,())
                t = (c, _L, k, R)
                if d: return unbalancedR(*t) + (None,)
                else: return store(*t), False, None
            if q  > k[0]:
                _R, d, m = _del(R)
                if empty(_R): return L, c=='B', k[0]
                t = (c, L, k, _R)
                if d: return unbalancedL(*t) + (m,)
                else: return store(*t), False, m

        blacken = lambda (_,L,x,R): ('B',L,x,R)
        d, _, _ = _del(D)
        return E if empty(d) else store(*blacken(get(d)))


    def preorder_traversal(self, d0):
        def _recons(d0):
            if d0 == self.E: return
            (c, dL, k, dR) = self.get(d0)
            yield c, k
            for L in _recons(dL): yield L
            for R in _recons(dR): yield R
        return _recons(d0)


class MerkleRedBlack(RedBlack):
    """Pass-through context (Identity)
    """
    def __init__(self, H=hash, E=()):
        self.H = H
        super(MerkleRedBlack,self).__init__(((),E))

    def store(self, c, (dL,L), k, (dR,R)):
        return (self.H((c, dL, k, dR)), (c, (dL,L), k, (dR,R)))

    def get(self, (_,D)):
        return D


class HashTableRB(RedBlack):
    def __init__(self, H=hash, E=(), table=None, validate=True):
        self.H = H
        if table is None: table = {}
        self.table = table
        self.cache = {}
        self.validate = validate
        super(HashTableRB,self).__init__(E)

    def store(self, c, dL, k, dR):
        preimage = (c, dL, k, dR)
        try:
            # First check the preimage cache
            return self.cache[preimage]
        except KeyError:
            # Recompute the digest
            digest = self.H(preimage)
            self.cache[preimage] = digest
            try:
                assert self.table[digest] == preimage
            except KeyError:
                self.table[digest] = preimage
            return digest

    def get(self, digest):
        preimage = self.table[digest]
        if self.validate: assert self.H(preimage) == digest
        self.cache[preimage] = digest
        return preimage

    def reconstruct(self, digest):
        def _recons(d0):
            if self.empty(d0): return (),()
            try:
                preimage = self.get(d0)
                (c, dL, k, dR) = preimage
                return d0, (c, (dL, _recons(dL)), k, (dR, _recons(dR)))
            except KeyError:
                if not self.validate: return (),()
                else: raise
        return _recons(digest)

from binascii import hexlify
class RecordTraversal(MerkleRedBlack):
    def __init__(self, H=hash, E=(), emit=None):
        """Record a stream of "gets" from a passthrough tree
        """
        super(RecordTraversal,self).__init__(H, E)
        if emit is None:
            self.VO = []
            emit = self.VO.append
        self.emit = emit

    def get(self, (_,D)):
        c, (dL,_), k, (dR,_) = D
        self.emit((c, dL, k, dR))
        return D

class InstrumentTraversal(RecordTraversal):
    def __init__(self, *args, **kwargs):
        super(InstrumentTraversal,self).__init__(*args, **kwargs)
        self.get_count = 0
        self.put_count = 0
        self.get_set = set()
        self.put_set = set()

    def store(self, c, L, k, R):
        print 'Put:', self.put_count, hash((c, L, k, R))
        self.put_set.add((c,L[0],k,R[0]))
        self.put_count += 1
        return super(InstrumentTraversal,self).store(c, L, k, R)

    def get(self, (d0,D)):
        print 'Get:', self.get_count, hash((c, dL, k, dR))
        self.get_set.add((c,dL,k,dR))
        self.get_count += 1
        print 'Record:', (c, dL, k, dR)
        return super(InstrumentTraversal,self).store((d0,D)) 



class ReplayTraversal(HashTableRB):
    def __init__(self, VO, H=hash, E=()):
        super(ReplayTraversal,self).__init__(H, E)
        self.VO = iter(VO)

    def get(self, d0):
        preimage = self.VO.next()
        #print 'Replay:', d0, preimage
        assert self.H(preimage) == d0
        return preimage
