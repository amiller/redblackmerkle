"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012


MerkleSampler represents a set of elements. In addition to the usual 
set operations (query, insert, remove), this data structure also provides
   - select   # Return element at index i (i is in range 0..N-1)
   - verify

All of these operations require O(log N) time in the worst-case.

This structure is based on a Red-Black Merkle tree with an additional 
array that enables elements to be selected at random (uniformly). The
array index for each element is stored along in the tree, which allows
this selection to be verified. New elements are always inserted at the
end of the array, and removed elements are 'filled-in' by replacing
them with the last element.



Type definitions and common notations:

DA:
    A merkle sampler contains a tree and an array:

        (D, A) = DA

    where D is a red-black merkle tree and A is an array. There is a one-to-
    one mapping between elements in the tree and elements in the array

        (v,i)        is in the tree D if-and-only-if
        A[i] = v

    The number of elements N is needed to verify each operation, so it is 
    included in the digest of the sampler

        (D,A) = DA
        digest(DA) == digest(D), len(A))

    The empty sampler is represented by

        (), []


P:
    A verification object for sampler operations. The following constraint
    holds:

        verify(d0, v, i, P) == True    if-and-only-if

        digest(DA) == d0       and
        (v,P) == select(i, DA)

    The verification object can be used by simulate_insert to compute
    the resulting digest for a tree:

        forall v, DA such that    P = query(v, DA)
                           and    d0 = digest(DA)
        then:
            assert digest(insert(v, DA)) == \
                   digest(simulate_insert(d0, v))
"""

from authredblack import AuthRedBlack
import json
import math

class MerkleSampler():
    def __init__(self, digest=lambda _ : ''):
        self.ARB = AuthRedBlack(lambda *args: digest(json.dumps(args)))

    def digest(self, (D,A)):
        """The digest for the sampler includes the length of the array
        and the root hash of the tree
        """
        return (self.ARB.digest(D), len(A))

    def select(self, i, (D,A)):
        """Select the element at index location i (in 0..N-1) and return a 
        Verification Object
        Returns:
            v, P
            where v is the element, P is the proof object for search(v, D)
        """
        v = A[i]
        (_, P) = self.query(v, (D,A))
        return v, P

    def query(self, v, (D,A)):
        """Search for an element in the tree
        Returns:
            (i,    P)    if v is in the set
            (None, P) otherwise
            where P is the proof object for a search in D for (v,0)
        """
        P = self.ARB.search((v,0), D)
        if not P: return None, P
        for (_, ((_v,i), _, _)) in P[::-1]:
            if _v == v: return i, P
        return None, P

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

    def verify(self, d0, v, i, P):
        _, N = d0
        assert len(P) <= 4*math.ceil(math.log(N+1,2))
        for (_, ((_vi), _, _)) in P[::-1]:
            if _vi == (v,i):
                R = self.ARB.reconstruct(P)
                assert (i, P) == self.query(v, (R, None))
                return True
        raise ValueError

    def simulate_insert(self, d0, v, P):
        """If digest(DA) == d0, then this function returns
              digest(insert(v, DA))
        """
        digest, insert = self.ARB.digest, self.ARB.insert
        (_, N) = d0
        assert len(P) <= 4*math.log(N+1,2)
        R = self.ARB.reconstruct(P)
        assert (digest(R), N) == d0
        return (digest(insert((v,N), R)), N+1)

    def delete(self, v):
        raise NotImplemented
        i, proofA, _ = self.query(v)
        proofA = search(q, self.D)
