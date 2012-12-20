module RedBlack where

data Color = B | R deriving (Eq,Show,Read)
data RBP k = Leaf | T Color !(RBP k) k !(RBP k) deriving (Show,Eq,Read)

balanceL (T B (T R (T R a x b) y c) z d) = (T R (T B a x b) y (T B c z d))
balanceL (T B (T R a x (T R b y c)) z d) = (T R (T B a x b) y (T B c z d))
balanceL t = t

balanceR (T B a x (T R (T R b y c) z d)) = (T R (T B a x b) y (T B c z d))
balanceR (T B a x (T R b y (T R c z d))) = (T R (T B a x b) y (T B c z d))
balanceR t = t

turnB Leaf = Leaf
turnB (T _ l k r) = T B l k r

leaf k = T B Leaf k Leaf

insert q Leaf = leaf q
insert q t = turnB $ insert' q t

insert' :: Ord k => k -> RBP k -> RBP k
insert' q (T _ l@Leaf k r) | q < k = (T R (leaf q) q (T B l k r))
insert' q (T _ l k r@Leaf) | q > k = (T R (T B l k r) k (leaf q))
insert' q (T c l k r) | q < k = balanceL (T c (insert' q l) k r)
insert' q (T c l k r) | q > k = balanceR (T c l k (insert' q r))
insert' q (T _ _ k _) | q == k = error "inserting duplicate"

delete :: k -> RBP k -> RBP k
delete q (T _ Leaf k Leaf) = Leaf