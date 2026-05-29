pragma circom 2.0.0;

include "tsl_production_primitives.circom";

template RevocationNonMembershipProduction(depth) {
    signal input subject_hash;
    signal input key_hash;
    signal input revocation_pointer_hash;
    signal input value_commitment;
    signal input empty_leaf_commitment;
    signal input public_revocation_root;
    signal input sparse_leaf_index;
    signal input sibling_path[depth];
    signal input path_bits[depth];

    component value_hash = Poseidon(3);
    value_hash.inputs[0] <== subject_hash;
    value_hash.inputs[1] <== key_hash;
    value_hash.inputs[2] <== revocation_pointer_hash;
    value_hash.out === value_commitment;

    component index_hash = Poseidon(1);
    index_hash.inputs[0] <== value_commitment;
    index_hash.out === sparse_leaf_index;

    component path = PoseidonMerkleRoot(depth);
    path.leaf <== empty_leaf_commitment;
    for (var i = 0; i < depth; i++) {
        path.siblings[i] <== sibling_path[i];
        path.path_bits[i] <== path_bits[i];
    }
    path.root === public_revocation_root;
}

component main { public [subject_hash, key_hash, revocation_pointer_hash, value_commitment, public_revocation_root, sparse_leaf_index] } = RevocationNonMembershipProduction(16);
