"""
Andrew Miller <amiller@cs.ucf.edu>
May 2012

"""

from redblack import WeightSelectRedBlack
from Crypto.Hash import SHA256


class NotaryProtocol(object):
    def __init__(self, apply_transaction, RB):
        H = lambda x: '' if not x else SHA256.new(str(x)).hexdigest()[:8]
        self.WSRB = WeightSelectRedBlack(H)
        self.RB = RB
        self.apply_transaction = apply_transaction

    def replay_proofs(self, d0, VOs):
        digest = self.RB.digest
        replay = self.RB.replay
        it = iter(VOs)
        def proof(d0):
            try:
                while True:
                    d0 = yield replay(d0, it.next())
            except StopIteration:
                yield d0
        return proof(d0)

    def record_proofs(self, D):
        record = self.RB.record
        VOs = []
        d = [D] 
        def proof(D):
            while True:
                T = record(D)
                d0 = yield T
                D = T.reconstruct(d0)
                d[0] = D
                VOs.append(T.VO)
        return proof(D), VOs, d


class Directory(object):
    def __init__(self, protocol):
        self.protocol = protocol
        self.A = ((), {})
        self.txs = {}

    def commit_transaction(self, Tx):
        """
        Requires a CommitCap
        """
        protocol = self.protocol
        digest = protocol.WSRB.digest
        insert = protocol.WSRB.insert
        select = protocol.WSRB.select
        record = protocol.WSRB.record
        lower = protocol.RB

        (D,d) = self.A
        d = dict(d)
        (N,_) = digest(D)

        # Fetch the most recent tree from our timeline
        if N > 0:
            ((t,dE),_) = select(N-1, D)
            E = d[dE]
        else:
            t, E = -1, ()

        # Apply the transaction to the lower-level tree
        dE = lower.digest(E)
        proof, VO, result = protocol.record_proofs(E)
        protocol.apply_transaction(dE, Tx, proof)
        E, = result
        dE = lower.digest(E)

        # Insert the updated tree into the upper-level tree
        (W,_) = dE
        d[dE] = E
        D = insert(((t+1, dE), W), D)

        print "Directory advancing to", lower.digest(E)

        self.txs[t] = Tx
        self.A = (D,d)
        return VO

    def query_transaction(self, t):
        protocol = self.protocol
        lower = protocol.RB
        upper = protocol.WSRB

        # Grab our snapshot of the data at time t
        (D,d) = self.A
        ((_t,dE),_) = upper.search(((t, None), None), D)
        assert _t == t
        Tx = self.txs[t]
        E = d[dE]

        # Simulate applying the transaction and collect the proof
        proof, VO, _ = protocol.record_proofs(E)
        protocol.apply_transaction(dE, Tx, proof)

        return Tx, VO


class Verifier(object):
    """
    
    """
    def __init__(self, d0, t, protocol, directory):
        self.protocol = protocol
        self.directory = directory
        self.d0 = d0
        self.t = t

    def advance(self):
        protocol = self.protocol
        lower = protocol.RB

        # Ask the directory to give us a transaction and a proof
        Tx, VO = self.directory.query_transaction(self.t)

        # Replay the proof and simulate this transaction
        proof = protocol.replay_proofs(self.d0, VO)
        d0 = protocol.apply_transaction(self.d0, Tx, proof)

        print "verifier advancing from", self.d0, "to", d0
        self.d0 = d0
        self.t += 1
