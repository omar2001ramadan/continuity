// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract TrustIDRegistry {
    error TrustIDExists(bytes32 trustId);
    error TrustIDNotFound(bytes32 trustId);
    error NotController(bytes32 trustId, address caller);

    struct TrustIdentity {
        address controller;
        bytes32 activeKey;
        bytes32 policyCommitment;
        uint64 createdAt;
    }

    mapping(bytes32 => TrustIdentity) public identities;
    mapping(bytes32 => mapping(bytes32 => bool)) public revokedKeys;

    event TrustIDRegistered(bytes32 indexed trustId, address indexed controller, bytes32 activeKey);
    event KeyRotated(bytes32 indexed trustId, bytes32 indexed oldKey, bytes32 indexed newKey);
    event KeyRevoked(bytes32 indexed trustId, bytes32 indexed key, uint8 reason);

    function register(bytes32 trustId, bytes32 activeKey, bytes32 policyCommitment) external {
        if (identities[trustId].createdAt != 0) revert TrustIDExists(trustId);

        identities[trustId] = TrustIdentity({
            controller: msg.sender,
            activeKey: activeKey,
            policyCommitment: policyCommitment,
            createdAt: uint64(block.timestamp)
        });

        emit TrustIDRegistered(trustId, msg.sender, activeKey);
    }

    function rotateKey(bytes32 trustId, bytes32 oldKey, bytes32 newKey) external onlyController(trustId) {
        TrustIdentity storage identity = identities[trustId];
        if (identity.createdAt == 0) revert TrustIDNotFound(trustId);

        revokedKeys[trustId][oldKey] = true;
        identity.activeKey = newKey;
        emit KeyRotated(trustId, oldKey, newKey);
    }

    function revokeKey(bytes32 trustId, bytes32 key, uint8 reason) external onlyController(trustId) {
        revokedKeys[trustId][key] = true;
        if (identities[trustId].activeKey == key) {
            identities[trustId].activeKey = bytes32(0);
        }
        emit KeyRevoked(trustId, key, reason);
    }

    function getActiveKey(bytes32 trustId) external view returns (bytes32) {
        return identities[trustId].activeKey;
    }

    function isRevoked(bytes32 trustId, bytes32 key) external view returns (bool) {
        return revokedKeys[trustId][key];
    }

    modifier onlyController(bytes32 trustId) {
        TrustIdentity memory identity = identities[trustId];
        if (identity.createdAt == 0) revert TrustIDNotFound(trustId);
        if (identity.controller != msg.sender) revert NotController(trustId, msg.sender);
        _;
    }
}
