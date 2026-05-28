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

    out <== left * 1315423911 + right * 2654435761 + 29;
}

template DelegationRoot(depth) {
    signal input policy_leaf;
    signal input siblings[depth];
    signal input path_bits[depth];
    signal output root;

    signal current[depth + 1];
    signal left_delta[depth];
    signal right_delta[depth];
    signal left_selected[depth];
    signal right_selected[depth];
    current[0] <== policy_leaf;

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

template AgentScopeCompliance(depth, n) {
    signal input action_value;
    signal input max_value;
    signal input tool_allowed;
    signal input counterparty_allowed;
    signal input rate_limit_remaining;
    signal input human_approval_required;
    signal input human_approval_present;
    signal input parameter_values_hash;
    signal input parameters_commitment;
    signal input policy_leaf;
    signal input delegation_path[depth];
    signal input delegation_path_bits[depth];
    signal input delegation_chain_root;
    signal input action_hash;
    signal input policy_root;
    signal input subject_hash;
    signal output public_max_value;
    signal output public_action_hash;
    signal output public_policy_root;
    signal output public_subject_hash;
    signal output public_delegation_chain_root;

    signal diff;
    diff <== max_value - action_value;

    component value_bits = Num2Bits(n);
    value_bits.in <== diff;

    component rate_bits = Num2Bits(n);
    rate_bits.in <== rate_limit_remaining;

    component tool = BooleanAssert();
    tool.in <== tool_allowed;
    tool_allowed === 1;

    component counterparty = BooleanAssert();
    counterparty.in <== counterparty_allowed;
    counterparty_allowed === 1;

    component approval_required = BooleanAssert();
    approval_required.in <== human_approval_required;

    component approval_present = BooleanAssert();
    approval_present.in <== human_approval_present;
    human_approval_required * (human_approval_present - 1) === 0;

    parameter_values_hash === parameters_commitment;
    policy_leaf === policy_root;

    component path = DelegationRoot(depth);
    path.policy_leaf <== policy_leaf;
    for (var i = 0; i < depth; i++) {
        path.siblings[i] <== delegation_path[i];
        path.path_bits[i] <== delegation_path_bits[i];
    }
    path.root === delegation_chain_root;

    public_max_value <== max_value;
    public_action_hash <== action_hash;
    public_policy_root <== policy_root;
    public_subject_hash <== subject_hash;
    public_delegation_chain_root <== delegation_chain_root;
}

component main { public [max_value, action_hash, policy_root, subject_hash, delegation_chain_root] } = AgentScopeCompliance(4, 64);
