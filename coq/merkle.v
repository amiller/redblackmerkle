Require Import monads.  (* MathClasses library *)
Require Import monads_. (* monads_.v *)

(* Authenticated Data Structures (A general form of Merkle trees) *)

(* Define a type of functional maps. *)
(* TODO: Instantiate this by borrowing from FMap.FMapInterfaces Sord*)
Parameter Map : Set.
Parameter empty : Map.
Parameter size : Map -> nat.
Parameter k v : Set.
Parameter search : Map -> k -> option v.
Parameter insert : Map -> k -> v -> Map.
Parameter delete : Map -> k -> Map.


Section WithRange.
(* The environment initially chooses a type for the output of a hash 
   function. *)
Variable HRange : Set.

(* Given an HRange, the implementation must provide instances for each 
   of the following sets:

   HDomain: input to the hash function
   Tree:    the entire data structure - O(N)
   VO:      a path through a Tree (i.e., a Verification Object)used 
            to verify a single operation - O(log N)
   Digest:  a concise representation of a Tree - O(1)
*)

Class MerkleData := {
  HDomain : Set;
  Tree : Set;
  VO : Set;
  Digest : Set;
  Empty : Tree
}.

(* The implementation must also define several computations that
   execute in a monad of the environment's choice. The implementation
   has access only to the ordinary monadic composition 
   operators (bind and return), as well as a HashComputation.
   a number of computations in this Monad. *)
Section WithData.
Context (MD : MerkleData).
Definition HashComputation (M:Type->Type) := HDomain -> M HRange.

Class Computations (M:Type->Type) := {

    (* The _c computations take a full O(N) data structure (Tree) and
       return an O(log N) Verification Object (VO). The Server in a 
       two-party Authenticated Data Structures protocol will perform these 
       computations. *)
    digest_c : Tree -> M Digest;
    search_c : Tree -> k -> M VO;
    insert_c : Tree -> k -> v -> M (prod VO Tree);
    delete_c : Tree -> k -> M (prod VO Tree);

    (* The _v computations take an O(1) digest and an O(log N) VO
       and return the result of the corresponding 'Map' operation. 
       The Client in a two-party Authenticated Data Structures protocol 
       would perform this computation. *)
    search_v : Digest -> k -> VO -> M (option (option v));
    insert_v : Digest -> k -> v -> VO -> M (option Digest);
    delete_v : Digest -> k -> VO -> M (option Digest);

    (* The _f are the  computations take a pair of VOs and produce a 
       Collision if the VOs result in conflicting answers when applied 
       to the corresponding _v. *)
    search_f : Digest -> k -> VO -> VO -> M (option (HDomain*HDomain));
    insert_f : Digest -> k -> v -> VO -> VO -> M (option (HDomain*HDomain));
    delete_f : Digest -> k -> VO -> VO -> M (option (HDomain*HDomain))
}.
Definition MerkleImpl := forall `{Monad M}, HashComputation M -> Computations M.


(* Given a MerkleImpl, which provides computations under any monad,
   the algorithm requirements are expressed using two specific monads. *)
Section MerkleSpec.
Variable CC : MerkleImpl.

Variable h : HDomain -> HRange.
Definition Collision := {ab | match ab with (a, b) => 
                         a <> b /\ h a = h b end}.

(* First, a trivial computation the Identity monad is used to express the 
   functional correctness/security claims. *)
Definition HashIdC : HashComputation IdM := fun d => h d.
Definition CCM := CC IdM IdM_Me IdM_Return IdM_Bind IdentityMonad HashIdC.

(* Second, a computation in the State monad that increments a counter is
   used to express the complexity bounds. *)
Definition CountM := StateM nat.
Definition HashCountC : HashComputation CountM := fun d c => (S c, h d).
Definition CCC := CC CountM (StateM_Me nat) (StateM_Return nat) (StateM_Bind nat)
                  (StateMonad nat) HashCountC.

Class MerkleSpec := {

(* Requirement #1: Correctness *)
(* Define a mapping from Trees to Maps. This is a homomorphism 
   under each of the operations. Functional correctness is
   evaluated by using the IdM monad. 

   Every *_c computation should produce a VO such that when the
   corresponding *_v is applied to the VO, the result is the same
   as the corresponding functional map operation. *)

   T : Tree -> Map;
   T_empty : T Empty = empty;

   digest : Tree -> Digest := fun t => digest_c (Computations:=CCM) t;

   search_T : forall t k, match search_c (Computations:=CCM) t k
              with vo =>
                 search_v (Computations:=CCM) (digest t) k vo = Some (search (T t) k)
              end;

   insert_T : forall t k v, match insert_c (Computations:=CCM) t k v
              with (vo, t') => 
                 T t' = insert (T t) k v
              /\ insert_v (Computations:=CCM) (digest t) k v vo = Some (digest t')
              end;

   delete_T : forall t k, match delete_c (Computations:=CCM) t k
              with (vo, t') =>
                  T t' = delete (T t) k
               /\ delete_v (Computations:=CCM) (digest t) k vo = Some (digest t')
              end;


(* Requirement #2. Security *)
(* If there is a logical collision in the tree, meaning a pair of VO's 
   that produce different outputs under search_v for some inputs, then
   the corresponding search_f will compute a Collision in the original
   hash function. *)

   search_F : forall d k vo vo' r r', 
                      r <> r'
                   /\ search_v (Computations:=CCM) d k vo = Some r
                   /\ search_v (Computations:=CCM) d k vo' = Some r' ->
                      exists cc, search_f (Computations:=CCM) d k vo vo' = Some cc;

   insert_F : forall d k v vo vo' r r', 
                      r <> r'
                   /\ insert_v (Computations:=CCM) d k v vo = Some r
                   /\ insert_v (Computations:=CCM) d k v vo' = Some r' ->
                      exists cc, insert_f (Computations:=CCM) d k v vo vo' = Some cc;

   delete_F : forall d k vo vo' r r', 
                      r <> r'
                   /\ delete_v (Computations:=CCM) d k vo = Some r
                   /\ delete_v (Computations:=CCM) d k vo' = Some r' ->
                      exists cc, delete_f (Computations:=CCM) d k vo vo' = Some cc;


(* Requirement #3. Complexity *)
(* All of the computations must run in O(poly N) time. When each
   computation is run under the Count monad, the number of accesses
   to the hash function should be <= polybound N. N is determined
   by the size of the equivalent mapping. *)

   polybound : nat -> nat;

   search_c_C : forall t k, match search_c (Computations:=CCC) t k 0
                     with (c, _) => c <= polybound (size (T t)) end;
   insert_c_C : forall t k v, match insert_c (Computations:=CCC) t k v 0
                     with (c, _) => c <= polybound (size (T t)) end;
   delete_c_C : forall t k, match delete_c (Computations:=CCC) t k 0
                     with (c, _) => c <= polybound (size (T t)) end
}.
End MerkleSpec.
End WithData.
End WithRange.


Record MerkleInstance (HRange:Set) := {
   Types : MerkleData;
   Implementation : MerkleImpl HRange Types;
   Proofs : forall h : HDomain -> HRange, MerkleSpec HRange Types Implementation h
}.

(* Finally, this is the overall type of satisfactory solutions. *)
Definition MerkleSolution := forall HRange, MerkleInstance HRange.
