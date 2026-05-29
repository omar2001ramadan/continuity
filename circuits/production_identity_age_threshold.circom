pragma circom 2.0.0;

include "tsl_production_primitives.circom";

template IdentityAgeThresholdProduction(depth) {
    signal input creation_epoch_day;
    signal input current_epoch_day;
    signal input threshold_days;
    signal input subject_hash;
    signal input registry_salt;
    signal input registry_siblings[depth];
    signal input registry_path_bits[depth];
    signal input public_registry_root;

    signal age_days;
    age_days <== current_epoch_day - creation_epoch_day;

    component age_check = RangeAtLeast(64);
    age_check.value <== age_days;
    age_check.threshold <== threshold_days;

    component leaf_hash = Poseidon(3);
    leaf_hash.inputs[0] <== subject_hash;
    leaf_hash.inputs[1] <== creation_epoch_day;
    leaf_hash.inputs[2] <== registry_salt;

    component path = PoseidonMerkleRoot(depth);
    path.leaf <== leaf_hash.out;
    for (var i = 0; i < depth; i++) {
        path.siblings[i] <== registry_siblings[i];
        path.path_bits[i] <== registry_path_bits[i];
    }
    path.root === public_registry_root;
}

component main { public [subject_hash, current_epoch_day, threshold_days, public_registry_root] } = IdentityAgeThresholdProduction(16);
