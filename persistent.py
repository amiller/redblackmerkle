"""
PAD:
    A Persistent Authenticated Dictionary (PAD) is constructed as a tree of
    trees 
        (D,d) = PAD

    where 
        D is the upper-layer tree, and 
        d is a Python dict-like object whose values are the trees 
          in the lower-layer.
        M is the current block number

    The outer layer stores elements of the form:

        (t, k) = select(0, D)

    where 
        t is a sequence number (e.g., the block number, or any discrete time)
        p is the previous hash (forming a merkle chain overlay / blockchain)
        k is the root hash for a tree in the inner layer.


    Searching for an element in the current tree involves selecting the tree
    with the highest value of t, which will always be the last element.

        N,_ = digest(D)
        (t, k) = select(N-1, D)
        E = d[k]
        search(q, E)

    
    ((),{}) is the empty PAD.

"""
from redblack import WeightSelectRedBlack

from Crypto.Hash import SHA256        
H = lambda x: '' if not x else SHA256.new(str(x)).hexdigest()[:8]
WSRB = WeightSelectRedBlack(H)
reconstruct = WSRB.reconstruct
search = WSRB.search
insert = WSRB.insert
digest = WSRB.digest
select = WSRB.select

class PersistentAuthDict(object):
    def __init__(self, RB):
        self.RB = RB


    def digest(self, PAD):
        (D,_) = PAD
        return digest(D)


    def insert(self, q, PAD):
        (D,d) = PAD
        (N,_) = digest(D)

        # Find the last (most recent) tree
        if N > 0:
            ((t, k), _) = select(N-1, D)
            E = d[k]
        else:
            t = -1
            E = ()

        # Add the new element to our lower-tree
        dE_old = self.RB.digest(E)
        E, VO_E = self.RB.insert(q, E)

        # Now store this new tree in our table and add its digest
        # to the upper-level tree
        dE = self.RB.digest(E)
        (W,_) = dE
        d[dE] = E
        D, VO_D = insert(((t+1, dE), W), D)

        return (D,d), (VO_D, dE_old, VO_E)


    def search(self, q, PAD, t=None):
        (D,d) = PAD
        (N,_) = digest(D)
        if t is None: ((t, _), _) = select(N-1,D)
        ((_t, dE), _), VO_D = search(((t, None), None), D)
        assert _t == t
        E = d[dE]
        k, VO_E = self.RB.search(q, E)
        return k, (VO_D, dE, VO_E)
        

    def reconstruct(self, d0, (VO_D, dE, VO_E)):
        E = self.RB.reconstruct(dE, VO_E)
        return reconstruct(d0, VO_D), {dE: E}
