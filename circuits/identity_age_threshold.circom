pragma circom 2.0.0;

template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc = 0;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc += out[i] * (1 << i);
    }
    lc === in;
}

template BooleanAssert() {
    signal input in;
    in * (in - 1) === 0;
}

template Hash2() {
    signal input left;
    signal input right;
    signal output out;

    out <== left * 1315423911 + right * 2654435761 + 17;
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

template IdentityAgeThreshold(depth, n) {
    signal input creation_epoch_day;
    signal input current_epoch_day;
    signal input threshold;
    signal input subject_hash;
    signal input registry_leaf;
    signal input registry_path[depth];
    signal input registry_path_bits[depth];
    signal output public_threshold;
    signal output public_subject_hash;
    signal output public_registry_root;

    registry_leaf === subject_hash;

    signal age_days;
    age_days <== current_epoch_day - creation_epoch_day;

    signal diff;
    diff <== age_days - threshold;

    component bits = Num2Bits(n);
    bits.in <== diff;

    component path = SparsePathRoot(depth);
    path.leaf <== registry_leaf;
    for (var i = 0; i < depth; i++) {
        path.siblings[i] <== registry_path[i];
        path.path_bits[i] <== registry_path_bits[i];
    }

    public_threshold <== threshold;
    public_subject_hash <== subject_hash;
    public_registry_root <== path.root;
}

component main { public [threshold, subject_hash] } = IdentityAgeThreshold(4, 32);
