// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the `claim_registry` module.
//!
//! Scenarios covered:
//! - Happy-path: claim an address and verify the registry dynamic field.
//! - Duplicate-claim rejection (`EAlreadyClaimed`, error code 1).
//! - Address-mismatch rejection (`EAddressMismatch`, error code 0).

use bcs;
use fastcrypto::encoding::{Encoding, Hex};
use iota_keys::keystore::AccountKeystore;
use iota_macros::sim_test;
use iota_types::{
    IOTA_CLAIM_REGISTRY_OBJECT_ID, IOTA_FRAMEWORK_ADDRESS, IOTA_FRAMEWORK_PACKAGE_ID,
    base_types::{IotaAddress, ObjectID},
    crypto::SignatureScheme,
    effects::TransactionEffectsAPI,
    execution_status::ExecutionFailureStatus,
    object::Owner,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{Argument, CallArg, ObjectArg},
};
use move_command_line_common::error_bitset::ErrorBitset;
use move_core_types::ident_str;
use test_cluster::{TestCluster, TestClusterBuilder};

// ---------------------------------------------------------------------------
// Protocol-upgrade test (msim only)
// ---------------------------------------------------------------------------

/// Verify that `ClaimRegistry` is created via `EndOfEpochTransaction` when a
/// network started at protocol v25 upgrades to v26 (where
/// `enable_claim_registry` first activates).
#[cfg(msim)]
#[sim_test]
async fn test_claim_registry_created_on_protocol_upgrade() {
    use iota_protocol_config::ProtocolVersion;
    use iota_types::supported_protocol_versions::SupportedProtocolVersions;

    telemetry_subscribers::init_for_testing();

    const PRE: u64 = 25;
    const POST: u64 = 26;

    let test_cluster = TestClusterBuilder::new()
        .with_protocol_version(ProtocolVersion::new(PRE))
        .with_epoch_duration_ms(20000)
        .with_supported_protocol_versions(SupportedProtocolVersions::new_for_testing(PRE, POST))
        .build()
        .await;

    assert!(
        test_cluster
            .get_object_from_fullnode_store(&IOTA_CLAIM_REGISTRY_OBJECT_ID)
            .await
            .is_none(),
        "ClaimRegistry must NOT exist at genesis (protocol v{PRE})"
    );

    let system_state = test_cluster.wait_for_epoch(Some(1)).await;
    assert_eq!(
        system_state.protocol_version(),
        POST,
        "Expected protocol version {POST} after epoch 1"
    );

    let reg = test_cluster
        .get_object_from_fullnode_store(&IOTA_CLAIM_REGISTRY_OBJECT_ID)
        .await
        .expect("ClaimRegistry must exist after upgrade to protocol v{POST}");
    assert!(
        matches!(reg.owner(), Owner::Shared { .. }),
        "ClaimRegistry must be a shared object; got {:?}",
        reg.owner()
    );
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

async fn registry_call_arg(cluster: &TestCluster, mutable: bool) -> CallArg {
    let obj = cluster
        .get_object_from_fullnode_store(&IOTA_CLAIM_REGISTRY_OBJECT_ID)
        .await
        .expect("ClaimRegistry must exist at genesis");
    let Owner::Shared {
        initial_shared_version,
    } = obj.owner()
    else {
        panic!("ClaimRegistry must be a shared object");
    };
    CallArg::Object(ObjectArg::SharedObject {
        id: IOTA_CLAIM_REGISTRY_OBJECT_ID,
        initial_shared_version: *initial_shared_version,
        mutable,
    })
}

/// Builds a `PublicKey` result in a PTB from scheme-prefixed bytes.
fn add_from_prefixed_bytes(
    b: &mut ProgrammableTransactionBuilder,
    prefixed_pubkey_bytes: Vec<u8>,
) -> anyhow::Result<Argument> {
    let pk_bytes_arg = b.pure(prefixed_pubkey_bytes)?;
    Ok(b.programmable_move_call(
        IOTA_FRAMEWORK_PACKAGE_ID,
        ident_str!("public_key").to_owned(),
        ident_str!("from_prefixed_bytes").to_owned(),
        vec![],
        vec![pk_bytes_arg],
    ))
}

/// Build a PTB that calls `claim_registry::test_claim_account` twice on the
/// same address. The first call succeeds, the second aborts with
/// EAlreadyClaimed.
fn build_double_claim_pt(
    registry_arg: CallArg,
    prefixed_pubkey_bytes: Vec<u8>,
) -> anyhow::Result<iota_types::transaction::ProgrammableTransaction> {
    let mut b = ProgrammableTransactionBuilder::new();
    let reg = b.input(registry_arg)?;
    let pk = add_from_prefixed_bytes(&mut b, prefixed_pubkey_bytes)?;
    b.programmable_move_call(
        IOTA_FRAMEWORK_PACKAGE_ID,
        ident_str!("claim_registry").to_owned(),
        ident_str!("test_claim_account").to_owned(),
        vec![],
        vec![reg, pk],
    );
    b.programmable_move_call(
        IOTA_FRAMEWORK_PACKAGE_ID,
        ident_str!("claim_registry").to_owned(),
        ident_str!("test_claim_account").to_owned(),
        vec![],
        vec![reg, pk],
    );
    Ok(b.finish())
}

/// Build a PTB that calls `claim_registry::test_claim_account` once (expects
/// abort at call site for address-mismatch or other errors).
fn build_claim_pt(
    registry_arg: CallArg,
    prefixed_pubkey_bytes: Vec<u8>,
) -> anyhow::Result<iota_types::transaction::ProgrammableTransaction> {
    let mut b = ProgrammableTransactionBuilder::new();
    let reg = b.input(registry_arg)?;
    let pk = add_from_prefixed_bytes(&mut b, prefixed_pubkey_bytes)?;
    b.programmable_move_call(
        IOTA_FRAMEWORK_PACKAGE_ID,
        ident_str!("claim_registry").to_owned(),
        ident_str!("test_claim_account").to_owned(),
        vec![],
        vec![reg, pk],
    );
    Ok(b.finish())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Claiming the same address twice in one PTB must abort with `EAlreadyClaimed`
/// (code 1). Both calls share the same registry input: the first adds the
/// dynamic field, the second sees it and aborts. The unconsumed ticket from the
/// first call is never an issue because the whole transaction rolls back on
/// abort.
#[sim_test]
async fn test_claim_registry_duplicate_claim_fails() -> anyhow::Result<()> {
    telemetry_subscribers::init_for_testing();

    let mut cluster = TestClusterBuilder::new().build().await;

    let (derived_address, _mnemonic, _scheme) = cluster
        .wallet
        .config_mut()
        .keystore_mut()
        .generate_and_add_new_key(SignatureScheme::ED25519, None, None, None)?;

    let mut prefixed_pubkey_bytes: Vec<u8> = vec![0x00u8]; // Ed25519 flag
    prefixed_pubkey_bytes.extend(
        cluster
            .wallet
            .config()
            .keystore()
            .get_key(&derived_address)?
            .public()
            .as_ref(),
    );

    let rgp = cluster.get_reference_gas_price().await;
    cluster
        .fund_address_and_return_gas(rgp, Some(20_000_000_000), derived_address)
        .await;

    let registry_arg = registry_call_arg(&cluster, true).await;
    let pt = build_double_claim_pt(registry_arg, prefixed_pubkey_bytes)?;
    let tx = cluster
        .test_transaction_builder_with_sender(derived_address)
        .await
        .programmable(pt)
        .build();
    let (eff2, _) = cluster
        .execute_transaction_return_raw_effects(cluster.wallet.sign_transaction(&tx))
        .await?;

    assert!(
        eff2.status().is_err(),
        "Second claim must fail; got {:?}",
        eff2.status()
    );

    let (failure, _) = eff2.status().clone().unwrap_err();
    assert!(
        matches!(
            failure,
            ExecutionFailureStatus::MoveAbort(ref loc, code)
            if loc.module.name().as_str() == "claim_registry"
                && loc.module.address() == &IOTA_FRAMEWORK_ADDRESS
                && ErrorBitset::from_u64(code).unwrap().error_code() == Some(1)
        ),
        "Expected EAlreadyClaimed (code 1) from claim_registry; got {failure:?}"
    );

    Ok(())
}

/// Supplying a public key whose derived address does not match the sender must
/// abort with `EAddressMismatch` (error code 0).
#[sim_test]
async fn test_claim_registry_wrong_pubkey_fails() -> anyhow::Result<()> {
    telemetry_subscribers::init_for_testing();

    let cluster = TestClusterBuilder::new().build().await;

    let sender = cluster
        .wallet
        .config()
        .keystore()
        .addresses()
        .first()
        .cloned()
        .expect("test cluster must have at least one account");

    let mut wrong_prefixed: Vec<u8> = vec![0x00u8]; // Ed25519 flag
    wrong_prefixed.extend(
        Hex::decode("cc62332e34bb2d5cd69f60efbb2a36cb916c7eb458301ea36636c4dbb012bd88")
            .expect("valid hex"),
    );

    let registry_arg = registry_call_arg(&cluster, true).await;
    let pt = build_claim_pt(registry_arg, wrong_prefixed)?;
    let tx = cluster
        .test_transaction_builder_with_sender(sender)
        .await
        .programmable(pt)
        .build();
    let (effects, _) = cluster
        .execute_transaction_return_raw_effects(cluster.wallet.sign_transaction(&tx))
        .await?;

    assert!(
        effects.status().is_err(),
        "Wrong-pubkey claim must fail; got {:?}",
        effects.status()
    );

    let (failure, _) = effects.status().clone().unwrap_err();
    assert!(
        matches!(
            failure,
            ExecutionFailureStatus::MoveAbort(ref loc, code)
            if loc.module.name().as_str() == "claim_registry"
                && loc.module.address() == &IOTA_FRAMEWORK_ADDRESS
                && ErrorBitset::from_u64(code).unwrap().error_code() == Some(0)
        ),
        "Expected EAddressMismatch (code 0) from claim_registry; got {failure:?}"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Happy-path per-scheme tests
// ---------------------------------------------------------------------------

/// Returns scheme-prefixed public-key bytes for `address` using `flag` as the
/// first byte (0x00 = Ed25519, 0x01 = Secp256k1, 0x02 = Secp256r1).
fn prefixed_pk_for_address(
    cluster: &TestCluster,
    address: IotaAddress,
    flag: u8,
) -> anyhow::Result<Vec<u8>> {
    let mut v = vec![flag];
    v.extend(
        cluster
            .wallet
            .config()
            .keystore()
            .get_key(&address)?
            .public()
            .as_ref(),
    );
    Ok(v)
}

/// Exercises the full happy-path claim flow for one signature scheme:
/// generates a fresh key, funds it, calls `test_claim_account`, and verifies
/// that a shared `DummyAccount` was created whose object-ID equals the sender
/// address (`claim` derives the UID via `new_uid_from_hash(sender_addr)`).
async fn run_claim_happy_path(scheme: SignatureScheme, flag: u8) -> anyhow::Result<()> {
    telemetry_subscribers::init_for_testing();

    let mut cluster = TestClusterBuilder::new().build().await;

    let (address, _, _) = cluster
        .wallet
        .config_mut()
        .keystore_mut()
        .generate_and_add_new_key(scheme, None, None, None)?;

    let pk = prefixed_pk_for_address(&cluster, address, flag)?;

    let rgp = cluster.get_reference_gas_price().await;
    cluster
        .fund_address_and_return_gas(rgp, Some(20_000_000_000), address)
        .await;

    let registry_arg = registry_call_arg(&cluster, true).await;
    let pt = build_claim_pt(registry_arg, pk)?;
    let tx = cluster
        .test_transaction_builder_with_sender(address)
        .await
        .programmable(pt)
        .build();
    let (effects, _) = cluster
        .execute_transaction_return_raw_effects(cluster.wallet.sign_transaction(&tx))
        .await?;

    assert!(
        effects.status().is_ok(),
        "Claim must succeed for {scheme:?}; got {:?}",
        effects.status()
    );

    // The DummyAccount is shared; its object-ID must equal the sender address.
    let shared: Vec<_> = effects
        .created()
        .into_iter()
        .filter(|(_, owner)| matches!(owner, Owner::Shared { .. }))
        .collect();
    assert_eq!(
        shared.len(),
        1,
        "Expected exactly one shared object for {scheme:?}"
    );

    let (obj_ref, _) = &shared[0];
    let expected_id: ObjectID = address.into();
    assert_eq!(
        obj_ref.0, expected_id,
        "DummyAccount object-ID must equal sender address for {scheme:?}"
    );

    Ok(())
}

#[sim_test]
async fn test_claim_happy_path_ed25519() -> anyhow::Result<()> {
    run_claim_happy_path(SignatureScheme::ED25519, 0x00).await
}

#[sim_test]
async fn test_claim_happy_path_secp256k1() -> anyhow::Result<()> {
    run_claim_happy_path(SignatureScheme::Secp256k1, 0x01).await
}

#[sim_test]
async fn test_claim_happy_path_secp256r1() -> anyhow::Result<()> {
    run_claim_happy_path(SignatureScheme::Secp256r1, 0x02).await
}

/// MultiSig happy path: 1-of-2 multisig (two Ed25519 component keys, threshold
/// 1). Verifies that the Move `to_iota_address()` multisig derivation matches
/// the node's address and that the DummyAccount is created with the correct
/// object-ID.
#[sim_test]
async fn test_claim_happy_path_multisig() -> anyhow::Result<()> {
    use iota_test_transaction_builder::TestTransactionBuilder;
    use iota_types::{multisig::MultiSigPublicKey, utils::keys};

    telemetry_subscribers::init_for_testing();

    let cluster = TestClusterBuilder::new().build().await;

    // Two deterministic test key pairs (Ed25519, Secp256k1) reused across IOTA
    // tests.
    let ks = keys();
    let pk0 = ks[0].public();
    let pk1 = ks[1].public();

    // 1-of-2 multisig: either signer alone satisfies the threshold.
    let multisig_pk = MultiSigPublicKey::new(vec![pk0, pk1], vec![1, 1], 1)?;
    let multisig_addr = IotaAddress::from(&multisig_pk);

    // Prefixed bytes for `from_prefixed_bytes`: [0x03 flag] ||
    // BCS(MultiSigPublicKey).
    let mut prefixed = vec![0x03u8];
    prefixed.extend(bcs::to_bytes(&multisig_pk)?);

    let rgp = cluster.get_reference_gas_price().await;
    let gas = cluster
        .fund_address_and_return_gas(rgp, Some(20_000_000_000), multisig_addr)
        .await;

    let registry_arg = registry_call_arg(&cluster, true).await;
    let pt = build_claim_pt(registry_arg, prefixed)?;

    // Sign with key 0 only (bitmap bit 0 = key 0; threshold 1 is satisfied).
    let tx = TestTransactionBuilder::new(multisig_addr, gas, rgp)
        .programmable(pt)
        .build_and_sign_multisig(multisig_pk.clone(), &[&ks[0]], 0b01);

    let (effects, _) = cluster.execute_transaction_return_raw_effects(tx).await?;

    assert!(
        effects.status().is_ok(),
        "MultiSig claim must succeed; got {:?}",
        effects.status()
    );

    // DummyAccount is shared; its object-ID must equal the multisig address.
    let shared: Vec<_> = effects
        .created()
        .into_iter()
        .filter(|(_, owner)| matches!(owner, Owner::Shared { .. }))
        .collect();
    assert_eq!(shared.len(), 1, "Expected exactly one shared DummyAccount");

    let (obj_ref, _) = &shared[0];
    let expected_id: ObjectID = multisig_addr.into();
    assert_eq!(
        obj_ref.0, expected_id,
        "DummyAccount object-ID must equal the multisig address"
    );

    Ok(())
}
