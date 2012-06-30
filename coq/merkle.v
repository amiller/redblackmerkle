Require Import monads.

(* Authenticated Data Structures (Generalized Merkle Trees)

   Tree:   the entire data structure - O(N)
   VO:     a path through a Tree (i.e., a Verification Object)used 
           to verify a single operation - O(log N)
   Digest: a concise representation of a Tree - O(1)
*)

(* Let Digest be the range of an arbitrary hash function. Digest
   will be provided, although the implementation gets to select
   the Domain for the hash function. Once a Domain is defined,
   the implementation must be secure for all possible hash
   functions from this Domain. This allows us to define collisions 
   very generally. *)
Parameter Digest : Set.

Section WithDomain.
Context (Domain : Set).

Section WithHash.
Context (h : Domain -> Digest).
Definition Collision := {ab | match ab with (a, b) => 
                         a <> b /\ h a = h b end}.

Context `{Monad M}.
Parameter hash : Domain -> M Digest.

Section Instance.
Context (Tree : Set) (VO : Set).

(* An operation on a Tree takes an Input, produces an Output
   and may return a modified Tree. *)
Definition Operation {Tree} {In} {Out} := Tree -> In -> Tree * Out.

(* For any Operation f, Verify defines a type of secure wrapper that
   that acts on a Digest rather than on a Tree itself. The wrapper
   is consistent with the semantics of f and secure in this sense:
       Any Tree that has a matching Digest but that produces a different
       output under f can be used construct a hash collision.
*)
Definition Verify {Domain} {h : Domain -> Digest}
   {Tree} {digest : Tree -> Digest} {In} {Out} {VO}
   (f : Operation) :=
      forall (d:Digest) (i:In) (vo:VO),
      option {x : Digest * Out &
          forall (t : Tree),
              digest t = d /\ 
              x <> (match f t i with (t', o') => (digest t', o') end)
          -> Collision}.

(* Given a Verify wrapper for Operation f, Record defines a wrapper type
   over f that produces a VO (Verification Object) along with the output
   so that Verify produces some correct value.
*)
Definition Record {Domain} {h : Domain -> Digest}
   {Tree} {digest : Tree -> Digest} {In} {Out} {VO}
   {f : Operation}
   (verify : Verify (h:=h) (digest:=digest) f) :=
      forall (t:Tree) (i:In),
      {w : Digest * Out * VO | exists v, 
           verify (digest t) i (snd w) = Some v /\ projT1 v = fst w}.

Record MerkleSearchInstance {K} {V} {Domain} (h : Domain -> Digest) := {
       Tree;
       VO;
       empty : Tree;
       digest : Tree -> Digest;

       search : Tree -> K     -> Tree * option V;
       insert : Tree -> K * V -> Tree * unit;
       delete : Tree -> K * V -> Tree * unit;

       search_v : Verify (digest:=digest) (h:=h) (VO:=VO) search;
       insert_v : Verify (digest:=digest) (h:=h) (VO:=VO) insert;
       delete_v : Verify (digest:=digest) (h:=h) (VO:=VO) delete;

       search_r : Record search_v;
       insert_r : Record insert_v;
       delete_r : Record delete_v
}.

Record MerkleSearch (K:Set) (V:Set) := {
    Domain : Type;
    structure : forall h : Domain -> Digest, 
           MerkleSearchInstance (K:=K) (V:=V) h
}.

Definition test := {x : nat & x+8=10}.
Print existT.

Definition test_a : test := existT (fun x => x+8=10) 2 (fun _ => 2 + 8 = 10).
Print Verify.

Definition MerkleUnit K V  `{EqDec K} `{EqDec V} Digest : MerkleSearch K V Digest :=
   {|
     Domain := unit;
     structure h := {|
        Tree := unit;
        VO := unit;
        empty := tt;
        digest := h;

        search t k := None;
        insert t kv := tt;
        delete t kv := tt;

        search_v d k vo := Some (existT None (fun t prop => tt));
        insert_v d kv vo := None;
        delete_v d kv vo := None;

        search_r t k := None;
        insert_r t k := None;
        delete_r t k := None
     |}
   |}.


