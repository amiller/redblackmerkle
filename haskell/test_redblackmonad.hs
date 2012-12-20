{-# LANGUAGE FlexibleContexts #-}

import Data.IORef
import RedBlack
import Control.Monad.Identity
import Control.Monad 
import Control.Monad.State

test1 :: RedBlackMonad Int () m => m ()
test1 = do
  update (Nothing::(Maybe (Visit Int ())))

test2 :: RedBlackMonad Int () m => m ()
test2 = do
  update $ Just $ Visit (Red, 1::Int, Just ())

double :: State Integer ()
double = get >>= put . (* 2)

runStateOn ref st = do
  readIORef ref >>= writeIORef ref . \s -> let (s', x) = runState st s in x
--runStateOn ref st = atomicModifyIORef ref $ \s -> let (s', x) = runState st s in (x, s')

main :: IO ()
main = do
  myRef <- newIORef (Root (Leaf::(Tree (Visit Int ()))))
  runStateOn myRef $ do
    test2
    down L
    test2
  readIORef myRef >>= putStrLn . show

test ref n = replicateM_ n $ do
  runStateOn ref double
  readIORef ref >>= putStrLn . show