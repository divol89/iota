// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Account type backed by IOTA's built-in signature-scheme authenticators
/// (Ed25519, Secp256k1, Secp256r1, MultiSig, Passkey).
///
/// There are two creation paths:
///
/// - **Fresh accounts** (`create_account_v1`, `create_immutable_account_v1`):
///   allocate a new on-chain object ID and register it as an account.
///
/// - **Claimed accounts** (`claim_account_v1`, `claim_immutable_account_v1`):
///   intended for addresses that already exist on-chain.
///   `ClaimRegistry` records each address once to prevent double-claiming, then
///   returns a deterministic UID for the new account object so the object ID
///   matches the sender's address.
///
/// Both paths produce either a **mutable** shared-object account or an
/// **immutable** account:
///
/// - **Mutable** accounts can have their authenticator rotated after creation
///   via `account::rotate_auth_function_ref_v1`, and support adding, removing,
///   and mutating dynamic fields via the admin functions in this module.
/// - **Immutable** accounts are frozen at creation; neither the authenticator
///   nor any dynamic fields can ever be changed.
module iota::builtin_account;

use iota::account;
use iota::authenticator_function::AuthenticatorFunctionRefV1;
use iota::builtin_authenticator_functions;
use iota::claim_registry::{Self, ClaimRegistry};
use iota::dynamic_field;
use iota::public_key::PublicKey;
use iota::signature_scheme::{Self, SignatureScheme};

// === Errors ===

#[error(code = 0)]
const EInvalidSignatureScheme: vector<u8> = b"Invalid signature scheme.";

#[error(code = 10)]
const ETransactionSenderIsNotTheAccount: vector<u8> = b"Transaction must be signed by the account.";

// === Structs ===

public struct Account has key {
    id: UID,
}

// === Public Functions ===

/// Creates a new mutable shared account backed by the built-in authenticator
/// for `public_key`'s signature scheme.
///
/// The public key is stored as a dynamic field on the account so the
/// authenticator can validate future transactions.
///
/// Emits a `MutableAccountCreated` event on success.
public fun create_account_v1(public_key: PublicKey, ctx: &mut TxContext) {
    let account = make_fresh_account(public_key, ctx);
    let authenticator = resolve_builtin_authenticator(public_key.scheme());

    account::create_account_v1(account, authenticator);
}

/// Creates a new immutable account backed by the built-in authenticator for
/// `public_key`'s signature scheme.
///
/// Identical to `create_account_v1` but the resulting object is frozen and
/// the authenticator can never be rotated.
///
/// Emits an `ImmutableAccountCreated` event on success.
public fun create_immutable_account_v1(public_key: PublicKey, ctx: &mut TxContext) {
    let account = make_fresh_account(public_key, ctx);
    let authenticator = resolve_builtin_authenticator(public_key.scheme());

    account::create_immutable_account_v1(account, authenticator);
}

/// Claims an existing on-chain address as a mutable shared account backed by
/// the built-in authenticator for `public_key`'s signature scheme.
///
/// `registry` records the sender's address to prevent double-claiming and
/// returns a deterministic UID so the new account object's ID matches the
/// sender's address.
///
/// Aborts if the address has already been claimed.
///
/// Emits a `MutableAccountCreated` event on success.
public fun claim_account_v1(registry: &mut ClaimRegistry, public_key: PublicKey, ctx: &TxContext) {
    let account = make_account_for_claiming(registry, public_key, ctx);
    let authenticator = resolve_builtin_authenticator(public_key.scheme());

    account::create_account_v1(account, authenticator);
}

/// Claims an existing on-chain address as an immutable account backed by
/// the built-in authenticator for `public_key`'s signature scheme.
///
/// Identical to `claim_account_v1` but the resulting object is frozen and
/// the authenticator can never be rotated.
///
/// Aborts if the address has already been claimed.
///
/// Emits an `ImmutableAccountCreated` event on success.
public fun claim_immutable_account_v1(
    registry: &mut ClaimRegistry,
    public_key: PublicKey,
    ctx: &TxContext,
) {
    let account = make_account_for_claiming(registry, public_key, ctx);
    let authenticator = resolve_builtin_authenticator(public_key.scheme());

    account::create_immutable_account_v1(account, authenticator);
}

// === View Functions ===

/// Return the account's address.
public fun account_address(self: &Account): address {
    self.id.to_address()
}

/// Returns `true` if and only if `self` has a dynamic field with the specified `name`.
public fun has_field<Name: copy + drop + store>(self: &Account, name: Name): bool {
    dynamic_field::exists_(&self.id, name)
}

/// Borrows a reference to a dynamic field from the account.
///
/// This function is not gated to be called only by the account,
/// anybody can call it to read the account dynamic fields.
public fun borrow_field<Name: copy + drop + store, Value: store>(
    self: &Account,
    name: Name,
): &Value {
    dynamic_field::borrow(&self.id, name)
}

/// Borrows a reference to the attached `AuthenticatorFunctionRefV1` instance.
///
/// This function is not gated to be called only by the account,
/// anybody can call it to read the attached authenticator.
public fun borrow_auth_function_ref_v1(self: &Account): &AuthenticatorFunctionRefV1<Account> {
    account::borrow_auth_function_ref_v1(&self.id)
}

// === Admin Functions ===

/// Adds a dynamic field to the account.
///
/// Only the account itself can call this function.
public fun add_field<Name: copy + drop + store, Value: store>(
    self: &mut Account,
    name: Name,
    value: Value,
    ctx: &TxContext,
) {
    ensure_tx_sender_is_account(self, ctx);

    dynamic_field::add(&mut self.id, name, value);
}

/// Removes a dynamic field from the account.
///
/// Only the account itself can call this function.
public fun remove_field<Name: copy + drop + store, Value: store>(
    self: &mut Account,
    name: Name,
    ctx: &TxContext,
): Value {
    ensure_tx_sender_is_account(self, ctx);

    dynamic_field::remove(&mut self.id, name)
}

/// Borrows a mutable reference to a dynamic field from the account.
///
/// Only the account itself can call this function.
public fun borrow_field_mut<Name: copy + drop + store, Value: store>(
    self: &mut Account,
    name: Name,
    ctx: &TxContext,
): &mut Value {
    ensure_tx_sender_is_account(self, ctx);

    dynamic_field::borrow_mut(&mut self.id, name)
}

/// Rotates a dynamic field.
///
/// Only the account itself can call this function.
public fun rotate_field<Name: copy + drop + store, Value: store>(
    self: &mut Account,
    name: Name,
    value: Value,
    ctx: &TxContext,
): Value {
    ensure_tx_sender_is_account(self, ctx);

    let account_id = &mut self.id;
    let previous_value = dynamic_field::remove<_, Value>(account_id, name);
    dynamic_field::add(account_id, name, value);
    previous_value
}

// === Package Functions ===

// === Private Functions ===

/// Allocates a new `Account` object and attaches `public_key` to it.
fun make_fresh_account(public_key: PublicKey, ctx: &mut TxContext): Account {
    let mut account = Account { id: object::new(ctx) };
    builtin_authenticator_functions::attach_public_key(&mut account.id, public_key);
    account
}

/// Claims the sender's address from `registry` and attaches `public_key` to
/// the resulting `Account` object.
fun make_account_for_claiming(
    registry: &mut ClaimRegistry,
    public_key: PublicKey,
    ctx: &TxContext,
): Account {
    let mut account = Account { id: claim_registry::claim(registry, public_key, ctx) };
    builtin_authenticator_functions::attach_public_key(&mut account.id, public_key);
    account
}

/// Maps a `SignatureScheme` to the corresponding built-in `AuthenticatorFunctionRefV1`.
///
/// Aborts with `EInvalidSignatureScheme` for any scheme not supported by the built-in authenticators.
fun resolve_builtin_authenticator(
    signature_scheme: SignatureScheme,
): AuthenticatorFunctionRefV1<Account> {
    if (signature_scheme == signature_scheme::ed25519()) {
        builtin_authenticator_functions::ed25519_authenticator_function_ref_v1<Account>()
    } else if (signature_scheme == signature_scheme::secp256k1()) {
        builtin_authenticator_functions::secp256k1_authenticator_function_ref_v1<Account>()
    } else if (signature_scheme == signature_scheme::secp256r1()) {
        builtin_authenticator_functions::secp256r1_authenticator_function_ref_v1<Account>()
    } else if (signature_scheme == signature_scheme::multisig()) {
        builtin_authenticator_functions::multisig_authenticator_function_ref_v1<Account>()
    } else if (signature_scheme == signature_scheme::passkey()) {
        builtin_authenticator_functions::passkey_authenticator_function_ref_v1<Account>()
    } else {
        abort EInvalidSignatureScheme
    }
}

/// Check that the sender of this transaction is the account itself.
fun ensure_tx_sender_is_account(self: &Account, ctx: &TxContext) {
    assert!(self.id.uid_to_address() == ctx.sender(), ETransactionSenderIsNotTheAccount);
}

// === Test Functions ===
