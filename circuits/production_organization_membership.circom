pragma circom 2.0.0;

include "tsl_production_primitives.circom";

template OrganizationMembershipProduction(depth) {
    signal input subject_hash;
    signal input org_hash;
    signal input issuer_hash;
    signal input valid_after_day;
    signal input expires_at_day;
    signal input current_epoch_day;
    signal input attestation_salt;
    signal input public_attestation_root;
    signal input issuer_registry_root;
    signal input attestation_siblings[depth];
    signal input attestation_path_bits[depth];
    signal input issuer_siblings[depth];
    signal input issuer_path_bits[depth];

    component not_before = RangeAtLeast(64);
    not_before.value <== current_epoch_day;
    not_before.threshold <== valid_after_day;

    component not_expired = RangeAtMost(64);
    not_expired.value <== current_epoch_day;
    not_expired.maximum <== expires_at_day;

    component attestation_leaf = Poseidon(5);
    attestation_leaf.inputs[0] <== subject_hash;
    attestation_leaf.inputs[1] <== org_hash;
    attestation_leaf.inputs[2] <== issuer_hash;
    attestation_leaf.inputs[3] <== expires_at_day;
    attestation_leaf.inputs[4] <== attestation_salt;

    component attestation_path = PoseidonMerkleRoot(depth);
    attestation_path.leaf <== attestation_leaf.out;
    component issuer_path = PoseidonMerkleRoot(depth);
    issuer_path.leaf <== issuer_hash;
    for (var i = 0; i < depth; i++) {
        attestation_path.siblings[i] <== attestation_siblings[i];
        attestation_path.path_bits[i] <== attestation_path_bits[i];
        issuer_path.siblings[i] <== issuer_siblings[i];
        issuer_path.path_bits[i] <== issuer_path_bits[i];
    }
    attestation_path.root === public_attestation_root;
    issuer_path.root === issuer_registry_root;
}

component main { public [subject_hash, org_hash, issuer_hash, current_epoch_day, public_attestation_root, issuer_registry_root] } = OrganizationMembershipProduction(16);
