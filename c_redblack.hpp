/*

llrb.hpp
Andrew Miller <amiller@cs.ucf.edu> <amiller@dappervision.com>
October 2012

A generic implementation of Left-Leaning RedBlack Trees [1,2]. 

Unlike in most RedBlack tree implementations [3,4], the 
tree structure itself is not assumed to reside in memory, and the edges
are not assumed to be pointers. Instead, the LLRB-tree operations are 
defined as traversals over a "Zipper" [5] machine, which exposes a few 
instructions for traversing and modifying a local context within a tree.

Specializations include:

1. Default/identity: an ordinary pointer-based tree in memory 
   (see c_redblack_main.cpp)

2. Merkle trees: the tree is augmented with hash digests stored
   at each node.

3. Merkle validation: the tree does not reside in memory, but
   instead the operations are "simulated" using an (untrusted)
   Verification Object (a sequence of data containing just the
   nodes visited, in order)


[1] Left-Leaning Red Black Trees. 
Robert Sedgewick
http://www.cs.princeton.edu/~rs/talks/LLRB/RedBlack.pdf
http://www.cs.princeton.edu/~rs/talks/LLRB/LLRB.pdf

[2] Purely Functional Left-Leaning Red Black Trees
Kazu Yamamoto. 2011
http://www.mew.org/~kazu/proj/red-black-tree/

[3] sys/tree.h  (in BSD standard lib)
Niels Provos. 2002. 
http://fxr.watson.org/fxr/source/sys/tree.h

[4] rb.h
Jason Evans. 2010
http://www.canonware.com/rb/

[5] Functional Pearl: The Zipper
Gerard Huet. 1996
http://www.st.cs.uni-saarland.de/edu/seminare/2005/advanced-fp/docs/huet-zipper.pdf

*/


#include <vector>
#include <ostream>
#include <boost/optional/optional.hpp>


namespace rbm {

    enum Color {RED, BLACK};
    enum Child {LEFT, RIGHT};

    std::ostream& operator<<(std::ostream &o, Color n) { switch(n){
        case RED: return o<<"R";
        case BLACK: return o<<"B";
        default: return o<<"(invalid value)"; }}

    template <typename Key, typename Value>
    struct Visit {
        Color c;
        Key k;
        boost::optional<Value> v;
        Visit(Color c, Key k) : c(c), k(k) {};
        Visit(Color c, Key k, Value v) : c(c), k(k), v(v) {};
    };

    template <typename Key, typename Value>
    std::ostream& operator<<(std::ostream &o, Visit<Key,Value> v) {
        o << "('" << v.c << "', " << v.k;
        if (v.v) o << ":" << *v.v;
        return o << ")";
    }

    template <typename Key, typename Value>
    class RedBlackZipper {
    public:
        virtual void down(Child d) = 0;
        virtual void up() = 0;
        virtual bool empty() = 0;
        virtual struct Visit<Key,Value> visit() = 0;

        virtual void modify(Visit<Key,Value>) = 0;
        virtual void leaf(Visit<Key,Value>) = 0;
        virtual void clear() = 0;

        virtual void push() = 0;
        virtual void pop() = 0;
        virtual void swap() = 0;

        inline Color color() { return this->visit().c; };
        inline void setColor(Color c) { 
            Visit<Key,Value> v = visit();
            v.c = c;
            modify(v);
        }

        inline void left() { down(LEFT); };
        inline void right() { down(RIGHT); };

        void flip() { setColor(color() == RED ? BLACK : RED); }

        template <typename T>
        T inChild(Child c, T (RedBlackZipper::*f)()) {
            T t;
            switch (c) {
            case LEFT: left(); t = (this->*f)(); up(); break;
            case RIGHT: right(); t = (this->*f)(); up(); }
            return t;
        }

        void inChild(Child c, void (RedBlackZipper<Key,Value>::*f)()) {
            switch (c) {
            case LEFT: left(); (this->*f)(); up(); break;
            case RIGHT: right(); (this->*f)(); up(); }
        }

        template <typename T>
        T inLeft(T (RedBlackZipper<Key,Value>::*f)()) { return inChild(LEFT, f); }
        template <typename T>
        T inRight(T (RedBlackZipper<Key,Value>::*f)()) { return inChild(RIGHT, f); }

        int colorFlip() {
            inLeft(&RedBlackZipper<Key,Value>::flip);
            inRight(&RedBlackZipper<Key,Value>::flip);
            flip();
        }

        void rotate(void (RedBlackZipper<Key,Value>::*left)(),
                    void (RedBlackZipper<Key,Value>::*right)()) {

            /* rotateRight (for rotateLeft, swap left and right)
             *    A            B 
             *  B   z   ==>  x   A
             * x y              y z
             */

            (this->*left)(); (this->*right)(); push();  // y
            up(); push();                               // B
            up(); Color c = color(); push();            // A
            swap();
            pop(); setColor(c);                         // B
            (this->*right)(); pop(); setColor(RED);     // A
            (this->*left)(); pop();                     // y
            up(); up();
        }

        void rotateRight() {
            rotate(&RedBlackZipper<Key,Value>::left,
                   &RedBlackZipper<Key,Value>::right);
        }

        void rotateLeft() {
            rotate(&RedBlackZipper<Key,Value>::right,
                   &RedBlackZipper<Key,Value>::left);
        }

        void insert(Key q, Value v) {
            _insert(q, v);
            setColor(BLACK);
        }

        void _insert(Key q, Value v) {
            if (empty()) return leaf(Visit<Key,Value>(BLACK, q, v));
            Visit<Key,Value> vv = visit();
            Key kk = vv.k;
            if (q == kk) throw ("Duplicate element inserted");
            else if (q < kk && inLeft(&RedBlackZipper<Key,Value>::empty)) {
                push(); leaf(Visit<Key,Value>(BLACK, q));
                right(); pop(); up();
                left(); _insert(q, v); up();
            } else if (q > kk && inRight(&RedBlackZipper<Key,Value>::empty)) {
                push(); leaf(Visit<Key,Value>(BLACK, kk));
                left(); pop(); up();
                right(); _insert(q, v); up();
            } else if (q < kk) {
                left(); _insert(q, v); up();
            } else if (q > kk) {
                right(); _insert(q, v); up();
            }
        }
    };
}
