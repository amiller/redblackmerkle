import subprocess
import unittest
import random
from Crypto.Hash import SHA256
import json
import redblack; reload(redblack)
from redblack import RedBlack

H = lambda x: '' if not x else SHA256.new(json.dumps(x)).hexdigest()[:4]
RB = RedBlack(H)
digest = RB.digest
search = RB.search
insert = RB.insert
query = RB.query


def tree2dot(D):
    layer = """
digraph BST {
node [fontname="Arial"];

%s
}
    """

    def edges(D, level=0):
        if not D: return

        (c, L, (k, dL, dR), R) = D

        node = 'N%d_%s' % (level, k)
        color, shape = (('red','ellipse') if c == 'R' else 
                        ('black', 'ellipse'))
        yield '%s [label="%s || %d || %s", color=%s, shape=%s]\n' % \
            (node, dL[1], k, dR[1], color, shape)

        for dX,X,label in ((dL,L,'L'),(dR,R,'R')):
            if X: yield '%s -> N%d_%s;\n' % (node, level+1, X[2][0])
            elif dX[0]:
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
R = search(10, D)
tree2png('dots/test_reconstruct_r0.png', R)
tree2png('dots/test_reconstruct_1.png', insert(10, D))
tree2png('dots/test_reconstruct_r1.png', insert(10, R))

D = ()
values = range(30)
#random.shuffle(values)
for v in values: D = insert(v, D)
tree2png('dots/sequential.png', D)
