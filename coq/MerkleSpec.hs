
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeSynonymInstances #-}

module MerkleSpec where

import Control.Monad (liftM)
import Control.Monad.State (State, put, get)
import Control.Monad.Identity (Identity)

-- a hash is defined an arbitrary function from a domain to a range
class (Eq d, Eq r) => Hashable d r where
  hash_function :: d -> r

-- A computation that evaluates a hash function on some input from domain d.
-- The hash function is otherwise hidden, so it can't be evaluated 
-- except through this instruction
class (Hashable d r, Monad m) => HashComputation m d r where
  hash :: d -> m r
  

-- In the simplest case, the instruction evaluates hash_function
-- and otherwise has no effect.
instance (Hashable d r) => HashComputation Identity d r where
  hash d = return $ hash_function d

-- An alternate form of HashComputation keeps a stateful 'counter' that
-- gets incremented every time a hash is computed. 
instance (Hashable d r) => HashComputation (State Int) d r where
  hash d = do
    x <- get; 
    put $ x + 1; 
    return $ hash_function d


-- A MerkleStructure 
class (HashComputation m d r) => MerkleInstance vo tree k v m d r where
  search :: tree -> k -> m (vo, Maybe v)
  insert :: tree -> k -> v -> m (vo, r, tree)
  delete :: tree -> k -> v -> m (vo, r, tree)
  
  search_v :: r -> k -> vo -> m (Maybe (Maybe v))
  insert_v :: r -> k -> v -> vo -> m (Maybe r)
  delete_v :: r -> k -> v -> vo -> m (Maybe r)
  
  
  
-- Further requirements:
-- 1. Complexity when instantiate 