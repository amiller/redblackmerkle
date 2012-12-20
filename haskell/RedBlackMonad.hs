{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeSynonymInstances #-}

module RedBlack where

import Control.Monad.State

data Color = Red | Black deriving (Show, Eq)
data Child = L | R deriving (Show, Eq)
data Visit k v = Visit (Color, k, Maybe v) deriving (Show, Eq)

class RedBlackMonad k v m where
  visit :: m (Visit k v)
  update :: Maybe (Visit k v) -> m ()
  empty :: m Bool
  down :: Child -> m ()
  up :: m ()
  -- push :: m ()
  -- pop :: m ()
  -- swap :: m ()

-- 1. RedBlackMonad instance using a Zipper and a Tree

data Tree a = Leaf | Branch (Tree a) a (Tree a) deriving Show
data RedBlackZipper a = Root (Tree a) | Hole (RedBlackZipper a) Child (Tree a) deriving Show

focus :: RedBlackZipper a -> Tree a
focus (Root t) = t
focus (Hole _ _ t) = t

setFocus :: RedBlackZipper a -> Tree a -> RedBlackZipper a
setFocus (Root _) t = (Root t)
setFocus (Hole c d _) t = (Hole c d t)
  
instance (Ord k) => RedBlackMonad k v (State (RedBlackZipper (Visit k v))) where
  visit = get >>= return . f . focus
    where
      f (Branch _ v _) = v
      
  update mv = get >>= \x -> put $ setFocus x $ f mv $ focus x
    where
      f Nothing _ = Leaf
      f (Just v) (Branch l _ r) = (Branch l v r)
      f (Just v) Leaf = (Branch Leaf v Leaf)

  empty = get >>= return . f . focus
    where
      f Leaf = True
      f _ = False
      
  down c = get >>= \x -> put $ f c x $ focus x
    where
      f :: Child -> RedBlackZipper (Visit k v) -> Tree (Visit k v) -> RedBlackZipper (Visit k v)
      f L z (Branch l _ _) = (Hole z L l)
      f R z (Branch _ _ r) = (Hole z R r)
      
  up = return ()
      
--  up = get >>= 

-- instance (Monad) HashGraphMonad domain range m where

-- data Cxt a = Top | Left (Cxt a) (RB k d) | Right (Tree k d) (Cxt a)
      
--  Main.modify Nothing

-- instance (Hashable (Visit k v)) => 