
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}

import MerkleSpec

removeAll [] k = []
removeAll (k':ks) k
  | k' == k  = removeAll ks k
  | k' /= k  = k : removeAll ks k

instance (Eq k, HashComputation m [k] r) => MerkleInstance [k] [k] k () m [k] r where

  search ks k = return (ks, if k `elem` ks then Just () else Nothing)
  
  insert ks k () = do 
    h <- hash ks';
    return (ks, h, ks') 
      where ks' = k:ks
  
  delete ks k () = do
    h <- hash ks';
    return (ks, h, ks') 
      where ks' = removeAll ks k
  
  search_v r k vo = do
    r' <- hash vo;
    if r' /= r then
      return Nothing
      else return $ Just result 
    where
      result = if k `elem` vo then Just () else Nothing

  insert_v r k () vo = do
    r' <- hash vo;
    if r' /= r then
      return Nothing
      else do 
        r'' <- hash result
        return $ Just r''
    where
      result = k:vo

  delete_v r k () vo = do
    r' <- hash vo;
    if r' /= r then
      return Nothing
      else do 
        r'' <- hash result
        return $ Just r''
    where
      result = removeAll vo k