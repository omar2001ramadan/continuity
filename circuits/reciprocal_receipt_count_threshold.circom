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

template ReciprocalReceiptCountThreshold(n) {
    signal input reciprocal_receipt_count;
    signal input threshold;
    signal input subject_hash;
    signal output public_threshold;
    signal output public_subject_hash;

    signal diff;
    diff <== reciprocal_receipt_count - threshold;

    component bits = Num2Bits(n);
    bits.in <== diff;

    public_threshold <== threshold;
    public_subject_hash <== subject_hash;
}

component main { public [threshold, subject_hash] } = ReciprocalReceiptCountThreshold(32);
