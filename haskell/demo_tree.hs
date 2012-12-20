{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

import Data.String.Combinators
import Text.Printf
import Control.Monad
import Control.Monad.State
import Data.Foldable
import Data.Traversable hiding (forM)
import Prelude hiding (foldr, concat)
import System.Process
import System.IO hiding (hGetContents)
import System.IO.Strict (hGetContents)

import System.Random
import Data.Array.IO
import Control.Monad

import RedBlack hiding (leaf)

data Rose a = Branch a [Rose a] deriving (Show)
leaf a = Branch a []

deriving instance Functor Rose
deriving instance Foldable Rose
deriving instance Traversable Rose

incr = do 
  x <- get;
  put (x + 1);
  return x;
  
label :: Rose a -> Rose (Int, a)
label tree = evalState (Data.Traversable.mapM label' tree) 0
  where 
    label' a = incr >>= return . (flip (,) a)

labels :: Rose a -> Rose String
labels = fmap (\(n, _) -> printf "N_%d" n) . label

edges :: Rose a -> [(a, a)]
edges (Branch a bs) = (map ((,) a . val) bs) ++ concat (map edges bs)
  where
    val (Branch a _) = a

edgeString :: Rose String -> String
edgeString x = concat [printf "%s -> %s;\n" a b | (a,b) <- edges x]

-- nodeString :: Show a => Tree (String, String) -> String
-- nodeString (Leaf (n, a)) = printf "%s [label=\"%s\", color=%s, shape=%s];\n" n a
                    
-- edges :: Show a => Tree a -> [String]

type CharTree = Rose Char
type IntTree = Rose Int

testTree :: CharTree
testTree = 
  Branch 'a' [
    Branch 'b' [leaf 'c', leaf 'd'],
    Branch 'e' [leaf 'f', leaf 'g']
    ]

type Label = String
data Node = Point | Node Color Label deriving (Show)

dot :: Rose Node -> String
dot t = 
  preamble $$
  node $$
  edges $$ 
  finish
  where
    preamble = "\
\digraph BST {\
\node [fontname=\"Arial\"];"
    edges = edgeString labeled
    finish = "}"
    node = concat [printf "%s %s" id (nodeString n) | (id, n) <- zip (foldr (:) [] labeled) (foldr (:) [] t)]
    labeled = labels t

nodeString Point = "[shape=point, label=x];\n"
nodeString (Node c l) = 
  printf "[label=\"%s\" color=%s, shape=ellipse];\n" l (color c)
  where 
    color R = "red"
    color B = "black"

rbpToRose :: Show k => RBP k -> Rose Node
rbpToRose Leaf = leaf Point
rbpToRose (T c Leaf k Leaf) = leaf $ Node c $ show k
rbpToRose (T c l k r) = Branch (Node c $ show k) $ map rbpToRose [l, r]

rbpToRose' :: Show k => RBP k -> Rose Node 
rbpToRose' Leaf = leaf Point
rbpToRose' (T c l k r) = Branch (Node c $ show k) $ map rbpToRose' [l, r]

-- rbpToRose Leaf = leaf (B, "()")
-- rbpToRose (T c Leaf k Leaf) = leaf (B, "()")

dot2png :: String -> Handle -> IO ()
dot2png dot h = do
  (Just hin, _, _, p) <- 
    createProcess (shell "dot -Tpng"){ std_out = UseHandle h, std_in = CreatePipe }
  hPutStr hin dot
  hClose hin
  waitForProcess p; return ()

tree2png :: (Show k) => FilePath -> RBP k -> IO ()
tree2png path tree = withBinaryFile path WriteMode $ dot2png $ dot $ rbpToRose' tree

tt1 = foldr insert Leaf [1..10]


-- | Randomly shuffle a list
--   /O(N)/
shuffle :: [a] -> IO [a]
shuffle xs = do
  ar <- newArray n xs
  forM [1..n] $ \i -> do
    j <- randomRIO (i,n)
    vi <- readArray ar i
    vj <- readArray ar j
    writeArray ar j vi
    return vj
  where
    n = length xs
    newArray :: Int -> [a] -> IO (IOArray Int a)
    newArray n xs =  newListArray (1,n) xs

main :: IO ()
main = do
  x <- shuffle [1..100]
  y <- return $! foldr insert Leaf x
  tree2png "test.png" y
  return ()
  
main' :: IO ()
main' = do
  putStrLn $ show $ testTree
  putStrLn $ show $ tt1
  tree2png "test.png" tt1
