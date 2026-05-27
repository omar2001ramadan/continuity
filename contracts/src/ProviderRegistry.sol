// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ProviderRegistry {
    error NotOwner();

    struct Provider {
        bytes32 publicKey;
        bytes32 policyCommitment;
        bool active;
    }

    address public owner;
    mapping(bytes32 => Provider) public providers;
    mapping(bytes32 => mapping(bytes32 => bytes32)) public modelCards;

    event ProviderRegistered(bytes32 indexed providerId, bytes32 publicKey, bytes32 policyCommitment);
    event ModelRegistered(bytes32 indexed providerId, bytes32 indexed modelId, bytes32 modelCardCommitment);
    event ProviderRevoked(bytes32 indexed providerId, uint8 reason);

    constructor() {
        owner = msg.sender;
    }

    function registerProvider(bytes32 providerId, bytes32 publicKey, bytes32 policyCommitment) external onlyOwner {
        providers[providerId] = Provider({ publicKey: publicKey, policyCommitment: policyCommitment, active: true });
        emit ProviderRegistered(providerId, publicKey, policyCommitment);
    }

    function registerModel(bytes32 providerId, bytes32 modelId, bytes32 modelCardCommitment) external onlyOwner {
        modelCards[providerId][modelId] = modelCardCommitment;
        emit ModelRegistered(providerId, modelId, modelCardCommitment);
    }

    function revokeProvider(bytes32 providerId, uint8 reason) external onlyOwner {
        providers[providerId].active = false;
        emit ProviderRevoked(providerId, reason);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }
}
