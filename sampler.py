from authredblack import AuthRedBlack
import json
import random
import math
def random_index(seed, N):
    return random.Random(seed).randint(0,N-1)


class MerkleSampler():
    def __init__(self, 
                 digest=lambda _ : '',
                 prf=lambda x: random.Random(x)):
        self.H = lambda *args: digest(json.dumps(args))
        self.ARB = AuthRedBlack(self.H)
        self.prf = prf

    def digest(self, (D,A)):
        """The digest for the sampler includes the length of the array
        and the root hash of the tree
        """
        return self.H(self.ARB.digest(D), len(A))

    def query(self, v, (D,A)):
        """Search for an element in the set
        Returns:
            (i,    (P,N))    if v is in the set
            (None, (P,N)) otherwise
            where P is the proof object for a search in D for (v,0)
            and N is the number of elements in the array
        """
        P = self.ARB.search((v,0), D)
        if not P: return None, (P, len(A))
        (_, ((_v,i), _, _)) = P[-1]
        if _v == v: return i, (P, len(A))
        return None, (P, len(A))

    def verify_query(self, d0, v, (P,N)):
        assert len(P) < 4*math.ceil(math.log(N,2))
        R = self.ARB.reconstruct(P)
        assert self.H(self.ARB.digest(R), N) == d0
        assert P == self.ARB.search((v,0), R)
        return True

    def get_random(self, seed, (D,A)):
        """Draw a element at random (uniformly) and provide a Verification
        Object that can be used to verify it.
        Returns:
            (v,i), (P,N)
            where v is the element and i is its index in the array
        """
        i = self.prf(seed).randint(0,len(A)-1)
        v = A[i]
        _, PN = self.query(v, (D,A))
        return (v,i), PN

    def verify_random(self, d0, v, seed, (P,N)):
        self.verify_query(d0, v, (P,N))
        i = self.prf(seed).randint(0,N-1)
        (_, (_vi, _, _)) = P[-1]
        assert _vi == (v,i)
        return True

    def insert(self, v, (D,A)):
        """Add a new element to the set
        Returns:
             (D,A)   the updated tree and array
        """
        assert self.query(v, (D,A))[0] is None, \
            "Trying to insert duplicate %s" % v
        D = self.ARB.insert((v,len(A)), D)
        A.append(v)
        return (D,A)

    def simulate_insert(self, d0, v, (P,N)):
        """If digest(DA) == d0, then this function returns
              digest(insert(v, DA))
        """
        digest, insert = self.ARB.digest, self.ARB.insert
        assert len(P) < 4*math.ceil(math.log(N,2))
        R = self.ARB.reconstruct(P)
        assert self.H(digest(R), N) == d0
        return self.H(digest(insert((v,N), R)), N+1)

    def delete(self, v):
        raise NotImplemented
        i, proofA, _ = self.query(v)
        proofA = search(q, self.D)
