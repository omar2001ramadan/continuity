pragma circom 2.0.0;

include "tsl_production_primitives.circom";

template SetMembershipProduction(depth) {
    signal input subject_hash;
    signal input membership_salt;
    signal input set_id;
    signal input public_set_root;
    signal input membership_siblings[depth];
    signal input membership_path_bits[depth];

    component leaf_hash = Poseidon(3);
    leaf_hash.inputs[0] <== subject_hash;
    leaf_hash.inputs[1] <== membership_salt;
    leaf_hash.inputs[2] <== set_id;

    component path = PoseidonMerkleRoot(depth);
    path.leaf <== leaf_hash.out;
    for (var i = 0; i < depth; i++) {
        path.siblings[i] <== membership_siblings[i];
        path.path_bits[i] <== membership_path_bits[i];
    }
    path.root === public_set_root;
}

component main { public [subject_hash, set_id, public_set_root] } = SetMembershipProduction(16);
