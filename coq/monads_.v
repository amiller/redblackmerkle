Require Import monads.
Require Import canonical_names.

(* Identity Monad *)

Definition IdM : Type -> Type := fun A => A.
Definition IdM_Return : MonadReturn IdM := fun A a => a.
Definition IdM_Bind : MonadBind IdM := fun A B ma f => f ma.

(* TODO *)
(* Prove monad laws? *)
Proposition IdM_Me : forall A : Type, Equiv A -> Equiv (IdM A).
auto. Qed.

Instance IdentityMonad : Monad IdM (Me:=IdM_Me) (H:=IdM_Return) (H0:=IdM_Bind). 
admit. Defined.


(* State Monad *)
Section State.
Context (S : Type).
Context (S_equiv : Equiv S).

Definition StateM : Type -> Type := fun A => S -> prod S A.
Definition StateM_Return : MonadReturn StateM := fun A a s => (s, a).
Definition StateM_Bind : MonadBind StateM := fun A B m f r =>
  match m r with (s, a) => (f a) s end.
Definition StateM_Me: forall A : Type, Equiv A -> Equiv (StateM A). 
admit. Defined.

(* TODO *)
(* Prove monad laws? *)
Instance StateMonad : Monad StateM (Me:=StateM_Me) (H:=StateM_Return) (H0:=StateM_Bind).
admit. Defined.
End State.
