from sampler import MerkleSampler
import json
from Crypto.Hash import SHA256


H = lambda x: SHA256.new(str(x)).hexdigest()
MS = MerkleSampler(H)

get_random = MS.get_random
verify_random = MS.verify_random


def do_work(iv, k, (D,A), lookup):
    """
    1. Initialize an accumulator with 'iv'. 
    2. Using the current accumulator value as the as the seed to a PRF, 
       draw a random element from the set.
    3. Add the data for this element into the accumulator.
    4. Repeat (from 2) for k iterations.

    The final value of the accumulator is the work, which can be compared
    to a difficulty threshold.

    A verifier with only O(1) of state (the root hash) can verify the work
    using the O(k log N) verification object.

    The prover walks the verifier backwards through the work, beginning 
    with the final accumulator value. This means a malicious prover would
    have to expend O(2^k log N) effort to make the verifier expend 
    O(k log n). (This is a claim about DoS resistance)

    A verifier with O(N) of state (such as another worker) can verify the
    solution for theirself using O(k log N) effort and only O(1)
    communication (just the iv). However it may still be preferable to
    require an O(k) proof object for DoS resistance, as above.
    """
    acc = iv
    walk = []  # Collect the verification objects in reverse order
    for _ in range(k):
        # Draw a random element (and corresponding VO)
        (element, _), (VO, _) = get_random(acc, (D,A))
        data = lookup(element)
        walk.insert(0, (acc, VO, data))

        # Add the data for this iteration into the accumulator
        acc = H((acc, data))

    return acc, (walk, len(A))


def verify_work(d0, acc, (walk, N), k, threshold=1<<(256-16)):
    """
    First compare the threshold, then walk backwards.
    Walk backwards through the work using the O(k log N) 
    verification object.
    """
    assert long(acc, 16) < threshold
    assert len(walk) == k

    for (prev_acc, P, data) in walk:
        v = H(data)
        assert verify_random(d0, v, prev_acc, (P,N))
        assert acc == H((prev_acc, data))
        acc = prev_acc

    return True
