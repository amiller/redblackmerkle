import redblack; reload(redblack)
import persistent; reload(persistent)
import notary; reload(notary)
import toycoin; reload(toycoin)


from notary import Directory, Verifier, NotaryProtocol

from collections import defaultdict

verify_signature = lambda dTx, pub, sig: (sig.startswith('SIGNED_'+pub)
                                          and sig.endswith(dTx))

def sign(dTx, priv):
    assert priv.startswith('PRIVKEY_')
    return 'SIGNED_' + priv[8:] + dTx

Transaction = toycoin.Transaction(verify_signature)
digest_transaction = Transaction.digest_transaction
protocol = NotaryProtocol(Transaction.apply_transaction, Transaction.RB)

class Client():

    def __init__(self):
        self.pubs = 'A', 'B'
        self.privs = dict(A='PRIVKEY_Alice', B='PRIVKEY_Bob')
        self.spendable = defaultdict(lambda: {})

    def apply_transaction(self, Tx):
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



# Alice starts off with 100 tokens
directory = Directory(protocol)

genesis = (('genesis',0), ('A', 100))
walk = protocol.RB.walk

def initial_tree():
    E = protocol.RB.insert(genesis, walk(()))
    dE = protocol.RB.digest(E)
    D = protocol.WSRB.insert(((0,dE), 1), walk(()))
    d = {dE: E}
    A = (D,d)
    return A, dE

directory.A, d0 = initial_tree()
verifier = Verifier(d0, 0, protocol, directory)

client = Client()
client.spendable[genesis[1][0]][genesis[0]] = genesis[1][1]

def send_payment(src, dst, amt):
    Tx = client.make_transaction(src, dst, amt)
    directory.commit_transaction(Tx)
    verifier.advance()
    client.apply_transaction(Tx)

# Make some transactions
for _ in range(10):
    send_payment('A', 'B', 1)
send_payment('B', 'B', 10)
send_payment('B', 'A', 10)
