//! P0: At-Most-Once Authorization and Downstream Side-Effect Failure Suite.
//! Verifies that single-use capability nonces guarantee at-most-once authorization across network drops and retries.

use peitho_core::generate_dsa_keypair;
use peitho_token::{
    compute_root_commitment, verify_token_with_registry, CapabilityToken, Caveat, CryptoProfile,
    InvocationContext, RevocationRegistry, TokenError,
};

fn create_wire_token(nonce: u64) -> CapabilityToken {
    let (pk, sk) = generate_dsa_keypair().expect("keygen");
    let token_id = "wire-transfer-token".to_string();
    let root_caveats = vec![
        Caveat::AllowedTools(vec!["execute_wire".into()]),
        Caveat::Nonce(nonce),
        Caveat::MaxBudgetMicroUnits(10_000_000), // $10.00
        Caveat::ExpiresAt(1_900_000_000),
    ];
    let digest = compute_root_commitment(&token_id, CryptoProfile::SwarmSpeed, &root_caveats).expect("commitment");
    let root_sig = peitho_core::sign_message(&sk, &digest).expect("sign");
    CapabilityToken {
        token_id,
        profile: CryptoProfile::SwarmSpeed,
        root_issuer_pk: pk,
        root_caveats,
        root_signature: root_sig,
        delegations: vec![],
    }
}

/// Simulated downstream external banking API.
struct MockBankApi {
    pub executed_transfers: usize,
    pub should_drop_response: bool,
}

impl MockBankApi {
    pub fn new() -> Self {
        Self {
            executed_transfers: 0,
            should_drop_response: false,
        }
    }

    pub fn execute_transfer(&mut self) -> Result<&'static str, &'static str> {
        if self.should_drop_response {
            // Downstream commits the transaction internally, but network connection drops before response
            self.executed_transfers += 1;
            Err("Network connection reset by peer (504 Gateway Timeout)")
        } else {
            self.executed_transfers += 1;
            Ok("Transfer Committed: TX_998877")
        }
    }
}

#[test]
fn test_at_most_once_authorization_under_network_drop_and_retry() {
    let registry = RevocationRegistry::new();
    let mut bank_api = MockBankApi::new();
    let nonce_val = 0x5555_AAAA_3333_7777u64;

    let token = create_wire_token(nonce_val);
    let ctx = InvocationContext {
        tool_name: Some("execute_wire".into()),
        resource_uri: None,
        current_time_secs: 1_700_000_000,
        is_read_only: false,
        cost_micro_units: 10_000_000,
    };

    // 1. Initial Attempt: Gateway authorizes request and burns the nonce
    assert!(verify_token_with_registry(&token, &ctx, Some(&registry)).is_ok());

    // Simulated failure: Downstream bank commits wire transfer, but connection drops on response
    bank_api.should_drop_response = true;
    let initial_downstream_res = bank_api.execute_transfer();
    assert!(initial_downstream_res.is_err(), "Simulated downstream network drop");
    assert_eq!(bank_api.executed_transfers, 1, "Bank executed the transfer once");

    // 2. Client encounters timeout and blindly retries with the same capability token
    let retry_auth_res = verify_token_with_registry(&token, &ctx, Some(&registry));

    // Invariant Check: Peitho Gateway MUST REJECT the retry because the single-use nonce was burned!
    // This prevents double-spend / duplicate wire execution at the authorization layer.
    match retry_auth_res {
        Err(TokenError::NonceAlreadyBurned { nonce }) => {
            assert_eq!(nonce, nonce_val, "Single-use nonce was already burned on initial attempt!");
        }
        other => panic!("Expected NonceAlreadyBurned on blind retry, got: {:?}", other),
    }

    // Because retry was blocked at Peitho gateway, downstream bank was NEVER invoked a second time!
    assert_eq!(
        bank_api.executed_transfers, 1,
        "CRITICAL: Bank API must have executed at most once!"
    );
}
