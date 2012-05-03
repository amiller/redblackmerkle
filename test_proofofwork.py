import os
from binascii import hexlify, unhexlify
import numpy as np
import unittest
import random

import proofofwork; reload(proofofwork)
from proofofwork import do_work, verify_work
from proofofwork import get_random, verify_random, H, MS

insert = MS.insert
query = MS.query
digest = MS.digest


table = {}
k = 64
DA = (), []


for i in (3,5,8,6,4,11):
    table[H(i)] = i
    DA = insert(H(i), DA)

for i in range(100):
    iv = H(hexlify(os.urandom(20)))
    acc, PN = do_work(iv, k, DA, table.get)
    d0 = MS.digest(DA)
    assert verify_work(d0, acc, PN, k)


N = 1000
values = range(N)
table = {}
k = 64
DA = (), []

random.shuffle(values)
for v in values: 
    table[H(v)] = v
    DA = insert(H(v), DA)

while True:
    # Produce a hash with two 0's in the front
    threshold = 1<<(256-8)
    k = 128
    d0 = digest(DA)
    iv = H(os.urandom(20))
    acc, PN = do_work(iv, k, DA, table.get)
    if long(acc,16) < threshold:
        print acc
        assert verify_work(d0, acc, PN, k)
        break

        

if __name__ == "__main__":
    unittest.main()
