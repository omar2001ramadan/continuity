pragma circom 2.0.0;

include "tsl_production_primitives.circom";

template DelegationScopeProduction(depth) {
    signal input subject_hash;
    signal input agent_hash;
    signal input principal_hash;
    signal input action_hash;
    signal input parameter_values_hash;
    signal input policy_constraints_hash;
    signal input scope_commitment;
    signal input delegation_chain_root;
    signal input delegation_siblings[depth];
    signal input delegation_path_bits[depth];
    signal input human_approval_required;
    signal input human_approval_present;

    component approval_required_bit = AssertBit();
    approval_required_bit.in <== human_approval_required;
    component approval_present_bit = AssertBit();
    approval_present_bit.in <== human_approval_present;
    human_approval_required * (1 - human_approval_present) === 0;

    component leaf_hash = Poseidon(7);
    leaf_hash.inputs[0] <== subject_hash;
    leaf_hash.inputs[1] <== agent_hash;
    leaf_hash.inputs[2] <== principal_hash;
    leaf_hash.inputs[3] <== action_hash;
    leaf_hash.inputs[4] <== parameter_values_hash;
    leaf_hash.inputs[5] <== policy_constraints_hash;
    leaf_hash.inputs[6] <== scope_commitment;

    component path = PoseidonMerkleRoot(depth);
    path.leaf <== leaf_hash.out;
    for (var i = 0; i < depth; i++) {
        path.siblings[i] <== delegation_siblings[i];
        path.path_bits[i] <== delegation_path_bits[i];
    }
    path.root === delegation_chain_root;
}

component main { public [subject_hash, agent_hash, principal_hash, action_hash, parameter_values_hash, scope_commitment, delegation_chain_root] } = DelegationScopeProduction(16);
