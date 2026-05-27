// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract GovernanceRegistry {
    error NotOwner();

    address public owner;
    bool public emergencyPaused;
    mapping(bytes32 => bytes32) public policyCommitments;
    mapping(bytes32 => string) public policyPointers;

    event PolicyCommitmentSet(bytes32 indexed policyId, bytes32 commitment);
    event PolicyPointerSet(bytes32 indexed policyId, string pointer);
    event EmergencyPauseMetadataSet(bool paused, bytes32 metadataCommitment);

    constructor() {
        owner = msg.sender;
    }

    function setPolicyCommitment(bytes32 policyId, bytes32 commitment) external onlyOwner {
        policyCommitments[policyId] = commitment;
        emit PolicyCommitmentSet(policyId, commitment);
    }

    function setPolicyPointer(bytes32 policyId, string calldata pointer, bytes32 commitment) external onlyOwner {
        policyPointers[policyId] = pointer;
        policyCommitments[policyId] = commitment;
        emit PolicyPointerSet(policyId, pointer);
        emit PolicyCommitmentSet(policyId, commitment);
    }

    function setEmergencyPauseMetadata(bool paused, bytes32 metadataCommitment) external onlyOwner {
        emergencyPaused = paused;
        policyCommitments[keccak256("emergency_pause_metadata")] = metadataCommitment;
        emit EmergencyPauseMetadataSet(paused, metadataCommitment);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }
}
