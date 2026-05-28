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

    out <== left * 1315423911 + right * 2654435761 + 19;
}

template MerkleRoot(width) {
    signal input leaves[width];
    signal output root;

    component h0[4];
    component h1[2];
    component h2 = Hash2();

    for (var i = 0; i < 4; i++) {
        h0[i] = Hash2();
        h0[i].left <== leaves[i * 2];
        h0[i].right <== leaves[i * 2 + 1];
    }
    for (var j = 0; j < 2; j++) {
        h1[j] = Hash2();
        h1[j].left <== h0[j * 2].out;
        h1[j].right <== h0[j * 2 + 1].out;
    }
    h2.left <== h1[0].out;
    h2.right <== h1[1].out;
    root <== h2.out;
}

template ReciprocalReceiptCountThreshold(width, n) {
    signal input reciprocal_receipt_count;
    signal input threshold;
    signal input subject_hash;
    signal input receipt_leaves[width];
    signal input receipt_salts[width];
    signal input counterparty_commitments[width];
    signal input receipt_valid[width];
    signal output public_threshold;
    signal output public_subject_hash;
    signal output public_receipt_root;

    signal valid_sum[width + 1];
    valid_sum[0] <== 0;

    component valid_bits[width];
    for (var i = 0; i < width; i++) {
        valid_bits[i] = BooleanAssert();
        valid_bits[i].in <== receipt_valid[i];

        receipt_valid[i] * (receipt_leaves[i] - (subject_hash + receipt_salts[i] + counterparty_commitments[i])) === 0;
        valid_sum[i + 1] <== valid_sum[i] + receipt_valid[i];
    }

    signal diff;
    diff <== reciprocal_receipt_count - threshold;

    component bits = Num2Bits(n);
    bits.in <== diff;

    component root = MerkleRoot(width);
    for (var j = 0; j < width; j++) {
        root.leaves[j] <== receipt_leaves[j];
    }

    public_threshold <== threshold;
    public_subject_hash <== subject_hash;
    public_receipt_root <== root.root;
}

component main { public [threshold, subject_hash] } = ReciprocalReceiptCountThreshold(8, 32);
