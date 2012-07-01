Require Import monads.
Require Import monads_.

(* Authenticated Data Structures (Generalized Merkle Trees)

   Tree:   the entire data structure - O(N)
   VO:     a path through a Tree (i.e., a Verification Object)used 
           to verify a single operation - O(log N)
   Digest: a concise representation of a Tree - O(1)
*)

(* Let HRange be the range of an arbitrary hash function. HRange
   will be provided by the environment, although the implementation gets 
   to select the HDomain. Once an HDomain is defined,
   the implementation must satisfy all the requirements for all possible
   hash functions from this HDomain. This allows us to express Collisions
  very generally. *)

Context (HRange : Set).

(* Define a type of functional maps. *)
(* TODO: Instantiate this by borrowing from FMap.FMapInterfaces Sord*)
Parameter Map : Set.
Parameter empty : Map.
Parameter size : Map -> nat.
Parameter k v : Set.
Parameter search : Map -> k -> option v.
Parameter insert : Map -> k -> v -> Map.
Parameter delete : Map -> k -> Map.

Section WithDomain.
(* Introduce a Domain for a hash function, as well as an instance
   from Domain to Range. Define a Collision of two distinct elements
   from the Domain with the same image in Range. *)
Context (HDomain : Set).
Context (h : HDomain -> HRange).

Definition Collision := {ab | match ab with (a, b) => 
                         a <> b /\ h a = h b end}.

(* Define a family of Monads in which a computation 'hash' is 
   defined. We provide two instances of this family. *)
Class HashComputation `{M0:Monad M} :=
  hash_computation : HDomain -> M HRange.

(* The first instance is an identity monad, and the computation 
   simply evaluates the hash function and returns the result. This
   is suitable for a correctness proof. *)
Instance HashIdC : HashComputation (M0:=IdentityMonad) := 
  { hash_computation d := h d }.

(* The second instance includes a counter, and the hash computation
   increments the counter every time. *)
Instance HashCountC : HashComputation (M0:=CountMonad) :=
  { hash_computation d := fun c => (S c, h d) }.

(* A computation defined for the entire family of HashMonads can only
   be constructed by composing hash_computations using (return) and (>>=).
*)
Definition HashMonadComputation A := forall M `{Monad M} `{HashComputation}, M A.

(*- Define a MerkleInstance type containing several sets 
    and a handful of computations *)
Class MerkleData := {
  Tree : Set;
  VO : Set;
  Digest : Set;
  Empty : Tree
}.

(* The computations must be defined for all Monads supporting a hash computation *)
Class Computations M `{MerkleData} := {
    digest_c : Tree -> M Digest;
    search_c : Tree -> k -> M VO;
    insert_c : Tree -> k -> v -> M (prod VO Tree);
    delete_c : Tree -> k -> M (prod VO Tree);

    search_v : Digest -> k -> VO -> M (option (option v));
    insert_v : Digest -> k -> v -> VO -> M (option Digest);
    delete_v : Digest -> k -> VO -> M (option Digest);

    search_f : Digest -> k -> VO -> VO -> M (option Collision);
    insert_f : Digest -> k -> v -> VO -> VO -> M (option Collision);
    delete_f : Digest -> k -> VO -> VO -> M (option Collision)
}.

Class MerkleInstance := {
   MD : MerkleData;

   (* The computations must be defined over all monads with 
      an available HashComputation, (not just the h in our scope) *)
   CC : forall M `{HC:HashComputation}, Computations M;

   CCM := CC IdM (HC:=HashIdC);
   CCC := CC CountM (HC:=HashCountC);

(* Requirement #1: Correctness *)
(* Define a mapping from Trees to Maps. This is a homomorphism 
   under each of the operations. Functional correctness is
   evaluated by using the IdM monad. 

   Every *_c computation should produce a VO such that when the
   corresponding *_v is applied to the VO, the result is the same
   as the corresponding functional map operation. *)

   T : Tree -> Map;
   T_empty : T Empty = empty;


   digest : Tree -> Digest := fun t => digest_c t;
  
   search_T : forall t k, match search_c (M:=IdM) t k
              with vo =>
                 search_v (digest t) k vo = Some (search (T t) k)
              end;

   insert_T : forall t k v, match insert_c (M:=IdM) t k v
              with (vo, t') => 
                 T t' = insert (T t) k v
              /\ insert_v (digest t) k v vo = Some (digest t')
              end;

   delete_T : forall t k, match delete_c (M:=IdM) t k
              with (vo, t') =>
                  T t' = delete (T t) k
               /\ delete_v (digest t) k vo = Some (digest t')
              end;

(* Requirement #2. Security *)
(* If there are logical collisions in the tree, meaning a pair of VO's 
   that produce different outputs under search_v for some inputs, then
   the corresponding search_f will compute a Collision in the original
   hash function. *)

   search_F : forall d k vo vo' r r', 
                      r <> r'
                   /\ search_v (M:=IdM) d k vo = Some r
                   /\ search_v (M:=IdM) d k vo' = Some r' ->
                      exists cc, search_f (M:=IdM) d k vo vo' = Some cc;

   insert_F : forall d k v vo vo' r r', 
                      r <> r'
                   /\ insert_v (M:=IdM) d k v vo = Some r
                   /\ insert_v (M:=IdM) d k v vo' = Some r' ->
                      exists cc, insert_f (M:=IdM) d k v vo vo' = Some cc;

   delete_F : forall d k vo vo' r r', 
                      r <> r'
                   /\ delete_v (M:=IdM) d k vo = Some r
                   /\ delete_v (M:=IdM) d k vo' = Some r' ->
                      exists cc, delete_f (M:=IdM) d k vo vo' = Some cc;


(* Requirement #3. Complexity *)
(* All of the computations must run in O(poly N) time. When each
   computation is run under the Count monad, the number of accesses
   to the hash function should be <= polybound N. N is determined
   by the size of the equivalent mapping. *)

   polybound : nat -> nat;

   search_c_C : forall t k, match search_c (M:=CountM) t k 0
                     with (c, _) => c <= polybound (size (T t)) end;
   insert_c_C : forall t k v, match insert_c (M:=CountM) t k v 0
                     with (c, _) => c <= polybound (size (T t)) end;
   delete_c_C : forall t k, match delete_c (M:=CountM) t k 0
                     with (c, _) => c <= polybound (size (T t)) end
}.

End WithDomain.

Class MerkleSolution := {
   HDomain : Set;
   MI : forall h : HDomain -> HRange, MerkleInstance HDomain h
}.

