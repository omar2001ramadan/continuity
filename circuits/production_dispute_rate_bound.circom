pragma circom 2.0.0;

include "tsl_production_primitives.circom";

template DisputeRateBoundProduction(width, depth) {
    signal input subject_hash;
    signal input max_dispute_rate_bps;
    signal input public_receipt_root;
    signal input completed_leaves[width];
    signal input disputed_leaves[width];
    signal input completed_siblings[width][depth];
    signal input completed_path_bits[width][depth];
    signal input disputed_siblings[width][depth];
    signal input disputed_path_bits[width][depth];
    signal input completed_valid[width];
    signal input disputed_valid[width];

    signal completed_count[width + 1];
    signal disputed_count[width + 1];
    signal total_count;
    signal allowed_disputes_scaled;
    signal observed_disputes_scaled;
    completed_count[0] <== 0;
    disputed_count[0] <== 0;

    component completed_bit[width];
    component disputed_bit[width];
    component completed_leaf_hash[width];
    component disputed_leaf_hash[width];
    component completed_path[width];
    component disputed_path[width];
    for (var i = 0; i < width; i++) {
        completed_bit[i] = AssertBit();
        completed_bit[i].in <== completed_valid[i];
        disputed_bit[i] = AssertBit();
        disputed_bit[i].in <== disputed_valid[i];

        completed_leaf_hash[i] = Poseidon(2);
        completed_leaf_hash[i].inputs[0] <== subject_hash;
        completed_leaf_hash[i].inputs[1] <== completed_leaves[i];
        disputed_leaf_hash[i] = Poseidon(2);
        disputed_leaf_hash[i].inputs[0] <== subject_hash;
        disputed_leaf_hash[i].inputs[1] <== disputed_leaves[i];

        completed_path[i] = PoseidonMerkleRoot(depth);
        completed_path[i].leaf <== completed_leaf_hash[i].out;
        disputed_path[i] = PoseidonMerkleRoot(depth);
        disputed_path[i].leaf <== disputed_leaf_hash[i].out;
        for (var j = 0; j < depth; j++) {
            completed_path[i].siblings[j] <== completed_siblings[i][j];
            completed_path[i].path_bits[j] <== completed_path_bits[i][j];
            disputed_path[i].siblings[j] <== disputed_siblings[i][j];
            disputed_path[i].path_bits[j] <== disputed_path_bits[i][j];
        }
        (completed_path[i].root - public_receipt_root) * completed_valid[i] === 0;
        (disputed_path[i].root - public_receipt_root) * disputed_valid[i] === 0;
        completed_count[i + 1] <== completed_count[i] + completed_valid[i];
        disputed_count[i + 1] <== disputed_count[i] + disputed_valid[i];
    }

    total_count <== completed_count[width] + disputed_count[width];
    observed_disputes_scaled <== disputed_count[width] * 10000;
    allowed_disputes_scaled <== max_dispute_rate_bps * total_count;

    component bound = LessThan(32);
    bound.in[0] <== allowed_disputes_scaled;
    bound.in[1] <== observed_disputes_scaled;
    bound.out === 0;
}

component main { public [subject_hash, max_dispute_rate_bps, public_receipt_root] } = DisputeRateBoundProduction(16, 16);
