Require Import monads.

Definition IdM : Type -> Type := fun A => A.
Definition IdM_Return : MonadReturn IdM := fun A a => a.
Definition IdM_Bind : MonadBind IdM := fun A B ma f => f ma.

Instance IdentityMonad : Monad IdM (H:=IdM_Return) (H0:=IdM_Bind). 
admit. Defined.

Definition StateM S : Type -> Type := fun A => S -> prod S A.
Definition StateM_Return {S} : MonadReturn (StateM S) := fun A a s => (s, a).
Definition StateM_Bind {S} : MonadBind (StateM S) := fun A B m f r =>
  match m r with (s, a) => (f a) s end.

Definition CountM := StateM nat.
Definition CountM_Me : forall A : Type, canonical_names.Equiv A -> 
   canonical_names.Equiv (CountM A). admit. Defined.

Instance CountMonad : Monad CountM (Me:=CountM_Me) (H:=StateM_Return) (H0:=StateM_Bind).
admit. Defined.