import subprocess
import unittest
import random
from Crypto.Hash import SHA256
import json
import authredblack; reload(authredblack)
from authredblack import AuthRedBlack

H = lambda (c, k, hL, hR): SHA256.new(json.dumps((c,k,hL,hR))).hexdigest()[:4]
ARB = AuthRedBlack(H)
digest = ARB.digest
search = ARB.search
insert = ARB.insert
reconstruct = ARB.reconstruct
balance = ARB.balance
query = ARB.query


def tree2dot(D):
    layer = """
digraph BST {
node [fontname="Arial"];

%s
}
    """

    def edges(D, level=0):
        if not D: return

        (c, L, (k, hL, hR), R) = D

        node = 'N%d_%s' % (level, k)
        color, shape = (('red','ellipse') if c == 'R' else 
                        ('black', 'ellipse'))
        yield '%s [label="%s || %d || %s", color=%s, shape=%s]\n' % \
            (node, hL, k, hR, color, shape)

        for hX,X,label in ((hL,L,'L'),(hR,R,'R')):            
            if X: yield '%s -> N%d_%s;\n' % (node, level+1, X[2][0])
            elif hX:
                n = 'null_%d_%s_%s' % (level+1, k, label)
                yield '%s -> %s;\n' % (node, n)
                yield '%s [shape=point, label=x];\n' % (n)

        for s in edges(L, level+1): yield s
        for s in edges(R, level+1): yield s

    return layer % (''.join(edges(D)))
    


def dot2png(dot):
    from subprocess import PIPE
    P = subprocess.Popen('dot -Tpng'.split(), 
                         stdout=PIPE, stdin=PIPE, stderr=PIPE)
    stdout, stderr = P.communicate(dot)
    #print dot
    print stderr
    return stdout


def tree2png(filename, D):
    open(filename, 'w').write(dot2png(tree2dot(D)))


D = ()
for i in (5,3,7,9,11):
    D = insert(i, D)
    tree2png('dots/test_reconstruct_i%d.png'%i, D)


tree2png('dots/test_reconstruct_0.png', D)
r = reconstruct(iter(search(10, D)))
tree2png('dots/test_reconstruct_r0.png', r)
tree2png('dots/test_reconstruct_1.png', insert(10, D))
tree2png('dots/test_reconstruct_r1.png', insert(10, r))
