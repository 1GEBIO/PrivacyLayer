use dep::commitment;
use dep::merkle;
use dep::withdraw;
use dep::escrow;
use dep::lib::hash;

#[test]
fn integration_standard_flow() {
    let n1: Field = 111;
    let s1: Field = 222;
    let c1 = hash::compute_commitment(n1, s1);

    let n2: Field = 333;
    let s2: Field = 444;
    let c2 = hash::compute_commitment(n2, s2);

    let path1: [Field; 20] = [0; 20];
    let path2: [Field; 20] = [0; 20]; // Simple mockup

    let global_root = merkle::compute_merkle_root(c1, 0, path1);
    let nh1 = hash::compute_nullifier_hash(n1, global_root);
    let nh2 = hash::compute_nullifier_hash(n2, global_root);

    dep::withdraw::main(n1, s1, 0, path1, global_root, nh1, 0xABCD, 1_000, 0, 0);
    dep::withdraw::main(n2, s2, 1, path2, global_root, nh2, 0xEF01, 1_000, 0, 0);
}

#[test]
fn integration_escrow_release_flow() {
    let nullifier: Field = 0xAAAAAAAA;
    let secret: Field = 0xBBBBBBBB;
    let arbiter_secret: Field = 0xCCCCCCCC;
    let arbiter_hash = std::hash::pedersen_hash([arbiter_secret]);

    // 1. Creation - commitment with arbiter_hash bound
    let commitment = hash::compute_escrow_commitment(nullifier, secret, arbiter_hash);
    
    // 2. Mock Merkle path
    let hash_path: [Field; 20] = [0; 20];
    let root = merkle::compute_merkle_root(commitment, 5, hash_path);
    let nullifier_hash = hash::compute_nullifier_hash(nullifier, root);

    // 3. Witness - try withdraw with the arbiter reveal
    dep::escrow::main(
        nullifier, secret, 5, hash_path, root, nullifier_hash,
        0xRECP, // recipient
        5_000,  // amount
        0xRELY, // relayer
        50,     // fee
        arbiter_secret,
        arbiter_hash
    );
}

#[test(should_fail_with = "mismatch")]
fn integration_escrow_wrong_arbiter_secret_fails() {
    let arbiter_hash = std::hash::pedersen_hash([0x123]);
    let commitment = hash::compute_escrow_commitment(1, 2, arbiter_hash);
    let root = merkle::compute_merkle_root(commitment, 0, [0; 20]);
    
    dep::escrow::main(1, 2, 0, [0; 20], root, 999, 0x1, 100, 0, 0, 0x456, arbiter_hash);
}
