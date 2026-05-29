pragma circom 2.0.0;

include "tsl_production_primitives.circom";

template ReceiptCountThresholdProduction(width, depth) {
    signal input threshold_count;
    signal input subject_hash;
    signal input public_receipt_root;
    signal input receipt_leaves[width];
    signal input receipt_salts[width];
    signal input counterparty_commitments[width];
    signal input receipt_siblings[width][depth];
    signal input receipt_path_bits[width][depth];
    signal input receipt_valid[width];

    signal count[width + 1];
    count[0] <== 0;

    component bit_check[width];
    component leaf_hash[width];
    component path[width];
    for (var i = 0; i < width; i++) {
        bit_check[i] = AssertBit();
        bit_check[i].in <== receipt_valid[i];

        leaf_hash[i] = Poseidon(4);
        leaf_hash[i].inputs[0] <== subject_hash;
        leaf_hash[i].inputs[1] <== receipt_leaves[i];
        leaf_hash[i].inputs[2] <== receipt_salts[i];
        leaf_hash[i].inputs[3] <== counterparty_commitments[i];

        path[i] = PoseidonMerkleRoot(depth);
        path[i].leaf <== leaf_hash[i].out;
        for (var j = 0; j < depth; j++) {
            path[i].siblings[j] <== receipt_siblings[i][j];
            path[i].path_bits[j] <== receipt_path_bits[i][j];
        }
        (path[i].root - public_receipt_root) * receipt_valid[i] === 0;
        count[i + 1] <== count[i] + receipt_valid[i];
    }

    component threshold = RangeAtLeast(16);
    threshold.value <== count[width];
    threshold.threshold <== threshold_count;
}

component main { public [subject_hash, threshold_count, public_receipt_root] } = ReceiptCountThresholdProduction(16, 16);
