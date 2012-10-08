#include <cstdio>
#include <cassert>
#include <iostream>
#include <string>
#include <stack>
#include <vector>
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include "c_redblack.hpp"

using namespace rbm;

template <typename Key, typename Value>
struct SimpleNode {
    Color c;
    Key k;
    Value v;
    SimpleNode<Key,Value> *left;
    SimpleNode<Key,Value> *right;
    SimpleNode() : left(NULL), right(NULL) {};
};

template <typename Key, typename Value>
class SimpleZipper : public RedBlackZipper<Key,Value> {
public:
    void down(Child d);
    void up();
    bool empty();
    struct Visit<Key,Value> visit();
    
    void modify(Visit<Key,Value>);
    void leaf(Visit<Key,Value>);
    void clear();

    void push();
    void pop();
    void swap();

    std::stack<std::pair<Child, SimpleNode<Key,Value>*> > path;
    std::stack<SimpleNode<Key,Value>*> stack;
    SimpleNode<Key,Value> *focus;
};

template <typename Key, typename Value>
std::ostream& operator<<(std::ostream &o, SimpleNode<Key,Value> *n) {
    if (!n) return o << "()";
    o << "('" << n->c << "', " << n->left << ", (" << n->k;
    if (!n->left && !n->right) o << ":" << n->v;
    return o << "), " << n->right << ")";
}


template <typename Key, typename Value>
void SimpleZipper<Key,Value>::down(Child d) {
    assert(!empty());
    path.push(std::pair<Child,SimpleNode<Key,Value>*>(d, focus));
    switch (d) {
    case LEFT: focus = focus->left; break;
    case RIGHT: focus = focus->right; }
}

template <typename Key, typename Value>
void SimpleZipper<Key,Value>::up() {
    std::pair<Child,SimpleNode<Key,Value>*> p = path.top();
    path.pop();
    SimpleNode<Key,Value>* child = focus;
    focus = p.second;
    switch (p.first) {
    case LEFT: focus->left = child; break;
    case RIGHT: focus->right = child; }
}

template <typename Key, typename Value>
bool  SimpleZipper<Key,Value>::empty() {
    return focus == NULL;
}

template <typename Key, typename Value>
struct Visit<Key,Value> SimpleZipper<Key,Value>::visit() {
    assert(!empty());
    Visit<Key,Value> v(focus->c, focus->k);
    if (!focus->left && !focus->right)
        v.v.reset(focus->v);
    return v;
}


template <typename Key, typename Value>
void SimpleZipper<Key,Value>::modify(Visit<Key,Value> v) {
    focus->c = v.c;
    focus->k = v.k;
    if (v.v) focus->v = *v.v;
}

template <typename Key, typename Value>
void SimpleZipper<Key,Value>::leaf(Visit<Key,Value> visit) {
    assert(empty());
    focus = new SimpleNode<Key,Value>;
    focus->c = visit.c;
    focus->k = visit.k;
    if (visit.v) focus->v = *visit.v;
}

template <typename Key, typename Value>
void SimpleZipper<Key,Value>::clear() {
    if (!focus) return;
    this->left(); clear(); up();
    this->right(); clear(); up();
    delete focus;
    focus = NULL;
}


template <typename Key, typename Value>
void SimpleZipper<Key,Value>::push() {
    stack.push(focus);
    //std::cout << "push " << stack.top() << std::endl;
    focus = NULL;
}

template <typename Key, typename Value>
void SimpleZipper<Key,Value>::pop() {
    assert(empty());
    //std::cout << "pop " << stack.top() << std::endl;
    focus = stack.top(); stack.pop();
}

template <typename Key, typename Value>
void SimpleZipper<Key,Value>::swap() {
    SimpleNode<Key,Value> *a = stack.top(); stack.pop();
    SimpleNode<Key,Value> *b = stack.top(); stack.pop();
    stack.push(a); stack.push(b);
}

void random_insert(int n=2000000) {
    typedef SimpleZipper<int,char> Zipper;
    typedef Visit<int,char> Vis;

    srand ( unsigned ( time (NULL) ) );

    Zipper zipper = Zipper();
    std::vector<int> data;
    for (int i = 0; i < n; i++) {
        data.push_back(i);
    }
    random_shuffle(data.begin(), data.end());
    printf("Inserting %d elements\n", n);
    for (int i = 0; i < data.size(); i++) {
        zipper.insert(data[i], '\0');
    }
    printf("done\n");
}


int main(int argc, char *argv[]) {
    typedef SimpleZipper<std::string,std::string> Zipper;
    typedef Visit<std::string,std::string> Vis;
    Zipper zipper = Zipper();

    zipper.leaf(Vis(RED,"A"));
    zipper.left();
    zipper.leaf(Vis(BLACK,"B"));
    zipper.up();
    zipper.right();
    zipper.leaf(Vis(BLACK,"z","z"));
    zipper.up();

    Color c = zipper.color();

    printf("hello world %d %d %d\n", RED, BLACK, c);
    printf("empty %d\n", zipper.empty());


    std::cout << zipper.visit() << std::endl;
    zipper.left();
    std::cout << zipper.visit() << std::endl;
    zipper.up(); zipper.right();
    std::cout << zipper.visit() << std::endl;
    zipper.up();

    std::cout << zipper.focus << std::endl;
    zipper.rotateRight();
    std::cout << zipper.focus << std::endl;

    std::cout << zipper.visit() << std::endl;
    zipper.right();
    std::cout << zipper.visit() << std::endl;
    zipper.up();

    zipper.left(); zipper.leaf(Vis(BLACK,"x","x")); zipper.up();

    std::cout << zipper.focus << std::endl;
    zipper.colorFlip();
    std::cout << zipper.focus << std::endl;

    std::cout << "Insertion" << std::endl;
    zipper.clear();
    std::cout << zipper.focus << std::endl;
    zipper.insert("A","0");
    zipper.insert("B","0");
    zipper.insert("C","0");
    zipper.insert("D","0");
    zipper.insert("E","0");
    std::cout << zipper.focus << std::endl;

    random_insert();
}
