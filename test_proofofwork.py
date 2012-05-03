import os
from binascii import hexlify, unhexlify
import numpy as np
import unittest
import random
import time

import proofofwork; reload(proofofwork)
from proofofwork import do_work, verify_work
from proofofwork import get_random, verify_random, H, MS

insert = MS.insert
query = MS.query
digest = MS.digest


def build_cheating_table(DA, lookup):
    """
    Attempt to cheat at the work by building a function that's
    fast at solving the work puzzles, but that can't be used to
    validate queries with proportionally good efficiency.

    This approach involves building an O(N * log N) table that
    can be used to solve work faster. This is a tradeoff of
    increased storage for faster time. The proof-of-work only
    really measures time, so this is what a Bitcoin miner would
    want to do optimize their payout.

    The do_work() function below is faster because it doesn't
    actually access the tree.

    TODO: Finish this note

    However, this attempt at cheating still results in O(1)
    verification of queries, the work with no additional cost.
    -- So, why not just exercise the array?
    -- What about update costs?
    
    """

    D,A = DA
    table = {}
    N = len(A)
    for i in range(N):
        v = A[i]
        data = lookup(v)
        _, (V0, _) = query(v, DA)
        table[i] = (V0, data)

    print 'Built table'

    def do_work(iv, k, _, __):
        acc = iv
        walk = []
        for _ in range(k):
            i = MS.prf(acc).randint(0,N-1)
            VO, data = table[i]
            walk.insert(0, (acc, VO, data))
            acc = H((acc, VO, data))
        return acc, (walk, N)

    def verify_work(d0, acc, (walk, N), k):
        assert len(walk) == k
        for (prev_acc, VO, data) in walk:
            v = H(data)
            assert verify_random(d0, v, prev_acc, (VO,N))
            assert acc == H((prev_acc, VO, data))
            acc = prev_acc
        return True

    return do_work


class ProofOfWorkTest(unittest.TestCase):
    def setUp(self):
        values = range(1000)
        random.shuffle(values)
        self.table = {}
        self.k = 64
        self.DA = (), []

        for v in values: 
            self.table[H(v)] = v
            self.DA = insert(H(v), self.DA)

    def test_cheat_at_work(self):
        # Build the lookup table
        DA, table = self.DA, self.table
        cheat_at_work = build_cheating_table(DA, table.get)

        ivs = [H(os.urandom(20)) for _ in xrange(1000)]
        k = 16
        d0 = digest(DA)

        def verify(do_work):
            for iv in ivs:
                acc, PN = do_work(iv, k, DA, table.get)
                assert verify_work(d0, acc, PN, k)

        def timeit(do_work):
            t0 = time.clock()
            for iv in ivs:
                acc, PN = do_work(iv, k, DA, table.get)
            t1 = time.clock()
            return (t1-t0)/len(ivs)

        print "Normal work (s):", timeit(do_work)
        print "Faster work (s):", timeit(cheat_at_work)


    def test_work(self):
        DA, table = self.DA, self.table
        d0 = MS.digest(DA)
        k = 32

        for i in range(100):
            iv = H(os.urandom(20))
            acc, PN = do_work(iv, k, DA, table.get)
            assert verify_work(d0, acc, PN, k)


    def test_work_with_threshold(self):
        """
        Simulate the behavior of a Bitcoin miner.
        """
        DA, table = self.DA, self.table
        k = 32
        d0 = digest(DA)

        # Produce a hash with two 0's in the front
        threshold = 1<<(256-8)
        while True:
            iv = H(os.urandom(20))
            acc, PN = do_work(iv, k, DA, table.get)
            if long(acc,16) < threshold:
                print 'Found winning block:', acc
                assert verify_work(d0, acc, PN, k)
                break


if __name__ == "__main__":
    unittest.main()
