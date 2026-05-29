pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template AssertBit() {
    signal input in;
    in * (in - 1) === 0;
}

template Select2() {
    signal input bit;
    signal input left_when_zero;
    signal input right_when_zero;
    signal output left;
    signal output right;

    component bit_check = AssertBit();
    bit_check.in <== bit;
    left <== left_when_zero + bit * (right_when_zero - left_when_zero);
    right <== right_when_zero + bit * (left_when_zero - right_when_zero);
}

template PoseidonMerkleRoot(depth) {
    signal input leaf;
    signal input siblings[depth];
    signal input path_bits[depth];
    signal output root;

    signal current[depth + 1];
    current[0] <== leaf;

    component select[depth];
    component hash[depth];
    for (var i = 0; i < depth; i++) {
        select[i] = Select2();
        select[i].bit <== path_bits[i];
        select[i].left_when_zero <== current[i];
        select[i].right_when_zero <== siblings[i];

        hash[i] = Poseidon(2);
        hash[i].inputs[0] <== select[i].left;
        hash[i].inputs[1] <== select[i].right;
        current[i + 1] <== hash[i].out;
    }

    root <== current[depth];
}

template RangeAtLeast(nBits) {
    signal input value;
    signal input threshold;

    component less = LessThan(nBits);
    less.in[0] <== value;
    less.in[1] <== threshold;
    less.out === 0;
}

template RangeAtMost(nBits) {
    signal input value;
    signal input maximum;

    component less = LessThan(nBits);
    less.in[0] <== maximum;
    less.in[1] <== value;
    less.out === 0;
}
