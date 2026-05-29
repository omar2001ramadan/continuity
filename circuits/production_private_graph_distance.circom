pragma circom 2.0.0;

include "tsl_production_primitives.circom";

template PrivateGraphDistanceProduction(width) {
    signal input subject_hash;
    signal input threshold_distance_bps;
    signal input committed_local_neighborhood_root;
    signal input trusted_seed_commitment;
    signal input adversarial_seed_commitment;
    signal input aggregate_proof_commitment;
    signal input local_edge_weights_bps[width];
    signal input trusted_seed_scores_bps[width];
    signal input adversarial_seed_scores_bps[width];
    signal input local_edge_valid[width];

    signal trusted_mass[width + 1];
    signal adversarial_mass[width + 1];
    signal total_mass[width + 1];
    signal valid_weight[width];
    signal trusted_weighted[width];
    signal adversarial_weighted[width];
    trusted_mass[0] <== 0;
    adversarial_mass[0] <== 0;
    total_mass[0] <== 0;

    component valid_bit[width];
    for (var i = 0; i < width; i++) {
        valid_bit[i] = AssertBit();
        valid_bit[i].in <== local_edge_valid[i];
        valid_weight[i] <== local_edge_valid[i] * local_edge_weights_bps[i];
        trusted_weighted[i] <== valid_weight[i] * trusted_seed_scores_bps[i];
        adversarial_weighted[i] <== valid_weight[i] * adversarial_seed_scores_bps[i];
        trusted_mass[i + 1] <== trusted_mass[i] + trusted_weighted[i];
        adversarial_mass[i + 1] <== adversarial_mass[i] + adversarial_weighted[i];
        total_mass[i + 1] <== total_mass[i] + valid_weight[i] * 10000;
    }

    signal distance_numerator;
    distance_numerator <== trusted_mass[width] + (total_mass[width] - adversarial_mass[width]);

    component threshold = RangeAtLeast(64);
    threshold.value <== distance_numerator;
    threshold.threshold <== threshold_distance_bps * 10000;

    component aggregate_hash = Poseidon(5);
    aggregate_hash.inputs[0] <== subject_hash;
    aggregate_hash.inputs[1] <== committed_local_neighborhood_root;
    aggregate_hash.inputs[2] <== trusted_seed_commitment;
    aggregate_hash.inputs[3] <== adversarial_seed_commitment;
    aggregate_hash.inputs[4] <== distance_numerator;
    aggregate_hash.out === aggregate_proof_commitment;
}

component main { public [subject_hash, threshold_distance_bps, committed_local_neighborhood_root, trusted_seed_commitment, adversarial_seed_commitment, aggregate_proof_commitment] } = PrivateGraphDistanceProduction(16);
