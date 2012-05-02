from binascii import hexlify, unhexlify
import os

import proofofwork; reload(proofofwork)
from proofofwork import digest, search, insert, reconstruct, balance, verify
from proofofwork import respond, verify_response, do_work, verify_work, H


D = ()
table = {}
k = 128

for i in (3,5,8,6,4,6,11):
    table[H(i)] = i
    D = insert(H(i), D)


for i in range(100):
    iv = H(hexlify(os.urandom(20)))
    acc, (proof, data) = respond(iv, D, table.get)
    assert verify_response(digest(D), iv, proof, data) == acc


while True:
    threshold = 1<<(256-8)
    k = 128
    d0 = digest(D)
    iv = H(hexlify(os.urandom(20)))
    acc, proofs = do_work(D, iv, k, table.get)
    if long(acc,16) < threshold:
        print acc
        assert verify_work(d0, proofs, acc, k, threshold)
        break
