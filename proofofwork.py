from Crypto.Hash import SHA256
import json
import os

from binascii import hexlify, unhexlify
bytes_to_long = lambda b: long(hexlify(b), 16)


import authredblack; reload(authredblack)
from authredblack import AuthRedBlack

H = lambda *args: SHA256.new(json.dumps(args)).hexdigest()

ARB = AuthRedBlack(H)
digest = ARB['digest']
search = ARB['search']
insert = ARB['insert']
reconstruct = ARB['reconstruct']
balance = ARB['balance']
verify = ARB['verify']


def respond(acc, D, lookup):
    # Use the provided nonce as a seed to our PRF
    def traverse(D, acc):
        if not D: return acc, ()
        c, left, (k, dL, dR), right = D

        # Combine our current state with the data for this node
        acc = H(acc, c, k, dL, dR)

        # Use the new state to choose which way road to take
        child = left if (bytes_to_long(acc) & 1) else right
        acc, proof = traverse(child, acc)
        return acc, ((c, (k, dL, dR)),) + proof

    # We ended up at a random root node, now we need to find its data
    # and hash that too
    acc, proof = traverse(D, acc)
    _, (k, _, _) = proof[-1]

    data = lookup(k)
    acc = H(acc, data)
    return acc, (proof, data)


def verify_response(d0, iv, proof, data):
    def lookup(k): 
        assert H(data) == k
        return data
    r = reconstruct(iter(proof))
    assert digest(r) == d0
    acc, pd = respond(iv, r, lookup)
    assert pd == (proof, data)
    return acc


def do_work(D, iv, k, lookup):
    acc = iv
    proofs = []
    for _ in range(k):
        iv = acc
        acc, (proof, data) = respond(iv, D, lookup)
        proofs = [(iv, proof, data)] + proofs # Prepend this proof
    return acc, proofs


def verify_work(d0, proofs, acc, k, threshold=1<<(256-16)):
    assert long(acc, 16) < threshold
    assert len(proofs) == k
    for iv, proof, data in proofs:
        assert verify_response(d0, iv, proof, data) == acc
        acc = iv
    return True

