// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract RevocationRegistry {
    struct Revocation {
        bytes32 trustId;
        bytes32 key;
        uint8 reason;
        uint64 effectiveAt;
        bytes32 replacementKey;
        address submitter;
    }

    mapping(bytes32 => Revocation) public revocationsByHash;
    mapping(bytes32 => mapping(bytes32 => bytes32)) public latestRevocationByTrustIdKey;

    event RevocationRecorded(
        bytes32 indexed revocationHash,
        bytes32 indexed trustId,
        bytes32 indexed key,
        uint8 reason,
        uint64 effectiveAt
    );

    function recordRevocation(
        bytes32 trustId,
        bytes32 key,
        uint8 reason,
        uint64 effectiveAt,
        bytes32 replacementKey
    ) external returns (bytes32 revocationHash) {
        revocationHash = keccak256(abi.encode(trustId, key, reason, effectiveAt, replacementKey, msg.sender));
        revocationsByHash[revocationHash] = Revocation({
            trustId: trustId,
            key: key,
            reason: reason,
            effectiveAt: effectiveAt,
            replacementKey: replacementKey,
            submitter: msg.sender
        });
        latestRevocationByTrustIdKey[trustId][key] = revocationHash;

        emit RevocationRecorded(revocationHash, trustId, key, reason, effectiveAt);
    }

    function isRevoked(bytes32 trustId, bytes32 key, uint64 atTime) external view returns (bool) {
        bytes32 revocationHash = latestRevocationByTrustIdKey[trustId][key];
        if (revocationHash == bytes32(0)) return false;
        return revocationsByHash[revocationHash].effectiveAt <= atTime;
    }
}
