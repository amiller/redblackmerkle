from collections import defaultdict

import redblack; reload(redblack)
import toycoin; reload(toycoin)

#from toycoin import 
#from toycoin import search, digest, size, select, verify, insert, delete, query

verify_signature = lambda dTx, pub, sig: (sig.startswith('SIGNED_'+pub)
                                          and sig.endswith(dTx))

def sign(dTx, priv):
    assert priv.startswith('PRIVKEY_')
    return 'SIGNED_' + priv[8:] + dTx

Transaction = toycoin.Transaction(verify_signature)
digest_transaction = Transaction.digest_transaction
verify_transaction = Transaction.verify_transaction
apply_transaction = Transaction.apply_transaction
digest = Transaction.digest
select = Transaction.select
Block = toycoin.Block(window=None)


class Client():
    def __init__(self, d0):
        self.d0 = d0
        self.pubs = 'A', 'B'
        self.privs = dict(A='PRIVKEY_Alice', B='PRIVKEY_Bob')
        self.spendable = defaultdict(lambda: {})

    def apply_transaction(self, Tx, VO):
        self.d0 = verify_transaction(self.d0, Tx, VO)
        (inps, outs, _) = Tx

        for inp in inps:
            for table in self.spendable.values():
                try: del table[inp]
                except KeyError: pass

        dTx = digest_transaction(Tx)
        for i, (pub, amt) in enumerate(outs):
            if pub in self.pubs:
                self.spendable[pub][(dTx,i)] = amt

    def make_transaction(self, src, pub, amount):
        total_in = 0
        inputs = []
        for inp, amt in self.spendable[src].iteritems():
            total_in += amt
            inputs.append(inp)
            if total_in >= amount: break
        else: raise ValueError('Not enough tokens')
        inps = tuple(inputs)
        change = ((src, total_in - amount),) if total_in > amount else ()
        outs = ((pub, amount),) + change
        dTx = digest_transaction((inps, outs, ()))
        sigs = len(inps) * (sign(dTx, self.privs[src]),)
        return (inps, outs, sigs)


class Server():
    def __init__(self, D):
        self.D = D
        self.pendingCommits = []

    def submit_transaction(self, Tx):
        """
        Validate the transaction and add it to a pool. Store the updated tree 
        along with it, so we can check new transactions against this one. It 
        only requires O(M * log N) storage to hold M updated trees, only 
        O(log N) nodes must be rebuilt.
        """
        _, D = pendingCommits[-1]
        d0 = digest(D)
        D, VO = apply_transaction(Tx, D)
        assert verify_transaction(d0, Tx, VO)
        self.pendingCommits.append((Tx, D))

    def submit_block(self, B):
        """
        Block validation.

        1. First, check that the proof-of-work is valid, to guard againt
           DoS.
        2. Next, check all transactions against the current
        """
        pass

    def apply_transaction(self, Tx):
        self.D, VO = apply_transaction(Tx, self.D)
        return VO    


# Alice starts off with all 100 of the tokens
D, _ = apply_transaction(((),(('A', 100),),()), ())
server = Server(D)
client = Client(digest(D))
(inp, (pub,amt)) = select(0, D)
client.spendable[pub][inp] = amt

def send_payment(src, dst, amt):
    Tx = client.make_transaction(src, dst, amt)
    #print Tx
    VO = server.apply_transaction(Tx)
    client.apply_transaction(Tx, VO)

# Make some transactions
for _ in range(10):
    send_payment('A', 'B', 1)
send_payment('B', 'B', 10)
send_payment('B', 'A', 10)
