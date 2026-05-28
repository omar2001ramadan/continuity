pragma circom 2.0.0;

template BooleanAssert() {
    signal input in;
    in * (in - 1) === 0;
}

template Hash2() {
    signal input left;
    signal input right;
    signal output out;

    out <== left * 1315423911 + right * 2654435761 + 23;
}

template SparsePathRoot(depth) {
    signal input leaf;
    signal input siblings[depth];
    signal input path_bits[depth];
    signal output root;

    signal current[depth + 1];
    signal left_delta[depth];
    signal right_delta[depth];
    signal left_selected[depth];
    signal right_selected[depth];
    current[0] <== leaf;

    component bit_check[depth];
    component hash[depth];
    for (var i = 0; i < depth; i++) {
        bit_check[i] = BooleanAssert();
        bit_check[i].in <== path_bits[i];

        hash[i] = Hash2();
        left_delta[i] <== (siblings[i] - current[i]) * path_bits[i];
        left_selected[i] <== current[i] + left_delta[i];
        right_delta[i] <== (current[i] - siblings[i]) * path_bits[i];
        right_selected[i] <== siblings[i] + right_delta[i];
        hash[i].left <== left_selected[i];
        hash[i].right <== right_selected[i];
        current[i + 1] <== hash[i].out;
    }

    root <== current[depth];
}

template RevocationSetNonMembership(depth) {
    signal input empty_leaf_commitment;
    signal input queried_value_commitment;
    signal input non_membership_inverse;
    signal input sibling_path[depth];
    signal input leaf_index_bits[depth];
    signal input revocation_root;
    signal input subject_hash;
    signal output public_revocation_root;
    signal output public_value_commitment;
    signal output public_subject_hash;

    (queried_value_commitment - empty_leaf_commitment) * non_membership_inverse === 1;

    component path = SparsePathRoot(depth);
    path.leaf <== empty_leaf_commitment;
    for (var i = 0; i < depth; i++) {
        path.siblings[i] <== sibling_path[i];
        path.path_bits[i] <== leaf_index_bits[i];
    }

    path.root === revocation_root;

    public_revocation_root <== revocation_root;
    public_value_commitment <== queried_value_commitment;
    public_subject_hash <== subject_hash;
}

component main { public [revocation_root, queried_value_commitment, subject_hash] } = RevocationSetNonMembership(4);
