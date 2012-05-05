import os
from binascii import hexlify, unhexlify
import numpy as np
import unittest
import random
import time

import authredblack; reload(authredblack)
import proofofwork; reload(proofofwork)
from proofofwork import do_work, verify_work
from proofofwork import select, verify, H, ASRB, PRF

insert = ASRB.insert
query = ASRB.query
digest = ASRB.digest


def build_shortcut_table(D, lookup):
    """
    This is an attempt to cheat at the work by building a function 
    that's fast at solving the work puzzles, but that can't be used 
    to validate queries with proportionally better efficiency.

    It's possible to tradeoff off increased storage for faster queries.
    The proof-of-work scheme only measures time, so this is what a 
    'miner' would want to in order do optimize their payout. This
    approach involves building an O(N * log N) table that solves work
    puzzles with a single lookup.

    However, this attempt at cheating still results in O(log N) 
    verification of O(1) results (just the elment and index i) as
    shown with the verify_query construction below.
    """

    (_, N) = digest(D)
    table = {}
    for i in range(N):
        v, VO = select(i, D)
        data = lookup(v)
        table[i] = (data, VO)

    def table_worker(iv, k):
        acc = iv
        walk = []
        for _ in range(k):
            i = PRF(acc).randint(0, N-1)
            data, VO = table[i]
            walk.insert(0, (acc, data, VO))
            acc = H((acc, data, VO))
        return (acc, walk)

    # Construct a verifier that only requires O(1) input, using our table
    def verify_query(d0, v, i):
        data, VO = table[i]
        assert verify(d0, v, i, VO)
        return True

    return table_worker


class ProofOfWorkTest(unittest.TestCase):
    def setUp(self):
        values = range(1000)
        random.shuffle(values)
        table = {}
        D = ()
        for v in values: 
            table[H(v)] = v
            D = insert(H(v), D)
        self.k = 64
        self.D = D
        self.table = table

    def test_cheat_at_work(self):
        D, table = self.D, self.table

        # Build the lookup table
        normal_worker = lambda iv, k: do_work(iv, k, D, table.get)
        table_worker = build_shortcut_table(D, table.get)

        ivs = [H(os.urandom(20)) for _ in xrange(1000)]
        k = 16
        d0 = digest(D)

        def verify(worker):
            for iv in ivs:
                acc, VO = worker(iv, k)
                assert verify_work(d0, acc, VO, k)

        def timeit(worker):
            t0 = time.clock()
            for iv in ivs:
                acc, VO = worker(iv, k)
            t1 = time.clock()
            return (t1-t0)/len(ivs)

        print "Normal work (s):", timeit(normal_worker)
        print "Faster work (s):", timeit(table_worker)


    def test_work(self):
        d0 = digest(self.D)
        k = 32

        for i in range(100):
            iv = H(os.urandom(20))
            acc, VO = do_work(iv, k, self.D, self.table.get)
            assert verify_work(d0, acc, VO, k)


    def test_work_with_threshold(self):
        """
        Simulate the behavior of a Bitcoin miner.
        """
        d0 = digest(self.D)
        k = 32

        # Produce a hash with two 0's in the front
        threshold = 1<<(256-8)
        while True:
            iv = H(os.urandom(20))
            acc, VO = do_work(iv, k, self.D, self.table.get)
            if long(acc,16) < threshold:
                print 'Found winning block:', acc
                assert verify_work(d0, acc, VO, k)
                break


if __name__ == "__main__":
    unittest.main()
