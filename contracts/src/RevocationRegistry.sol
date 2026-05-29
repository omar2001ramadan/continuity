// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITrustIDRegistry {
    function getController(bytes32 trustId) external view returns (address);
}

contract RevocationRegistry {
    error NotOwner();
    error UnauthorizedRevocation(bytes32 trustId, address caller);
    error InvalidControllerSignature(bytes32 trustId, address recoveredSigner);

    struct Revocation {
        bytes32 trustId;
        bytes32 key;
        uint8 reason;
        uint64 effectiveAt;
        bytes32 replacementKey;
        address submitter;
    }

    address public owner;
    address public trustIDRegistry;
    mapping(address => bool) public authorizedSubmitters;
    mapping(bytes32 => Revocation) public revocationsByHash;
    mapping(bytes32 => mapping(bytes32 => bytes32)) public latestRevocationByTrustIdKey;
    mapping(bytes32 => mapping(bytes32 => bytes32[])) private revocationHistoryByTrustIdKey;

    event TrustIDRegistryUpdated(address indexed registry);
    event SubmitterAuthorizationUpdated(address indexed submitter, bool authorized);
    event RevocationRecorded(
        bytes32 indexed revocationHash,
        bytes32 indexed trustId,
        bytes32 indexed key,
        uint8 reason,
        uint64 effectiveAt
    );

    constructor() {
        owner = msg.sender;
        authorizedSubmitters[msg.sender] = true;
        emit SubmitterAuthorizationUpdated(msg.sender, true);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function setTrustIDRegistry(address registry) external onlyOwner {
        trustIDRegistry = registry;
        emit TrustIDRegistryUpdated(registry);
    }

    function setAuthorizedSubmitter(address submitter, bool authorized) external onlyOwner {
        authorizedSubmitters[submitter] = authorized;
        emit SubmitterAuthorizationUpdated(submitter, authorized);
    }

    function recordRevocation(
        bytes32 trustId,
        bytes32 key,
        uint8 reason,
        uint64 effectiveAt,
        bytes32 replacementKey
    ) external returns (bytes32 revocationHash) {
        _requireControllerOrAuthorizedSubmitter(trustId, msg.sender);
        revocationHash = _recordRevocation(trustId, key, reason, effectiveAt, replacementKey);
    }

    function recordRevocationWithAuthorization(
        bytes32 trustId,
        bytes32 key,
        uint8 reason,
        uint64 effectiveAt,
        bytes32 replacementKey,
        bytes calldata controllerSignature
    ) external returns (bytes32 revocationHash) {
        address controller = _controllerFor(trustId);
        address recoveredSigner = recoverControllerSigner(
            revocationAuthorizationHash(trustId, key, reason, effectiveAt, replacementKey),
            controllerSignature
        );
        if (controller == address(0) || recoveredSigner != controller) {
            revert InvalidControllerSignature(trustId, recoveredSigner);
        }
        revocationHash = _recordRevocation(trustId, key, reason, effectiveAt, replacementKey);
    }

    function isRevoked(bytes32 trustId, bytes32 key, uint64 atTime) external view returns (bool) {
        bytes32[] storage history = revocationHistoryByTrustIdKey[trustId][key];
        for (uint256 i = 0; i < history.length; i++) {
            if (revocationsByHash[history[i]].effectiveAt <= atTime) return true;
        }
        return false;
    }

    function revocationAuthorizationHash(
        bytes32 trustId,
        bytes32 key,
        uint8 reason,
        uint64 effectiveAt,
        bytes32 replacementKey
    ) public pure returns (bytes32) {
        return keccak256(abi.encode("tsl.revocation.authorization.v1", trustId, key, reason, effectiveAt, replacementKey));
    }

    function recoverControllerSigner(bytes32 authorizationHash, bytes calldata signature) public pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", authorizationHash));
        return ecrecover(messageHash, v, r, s);
    }

    function _recordRevocation(
        bytes32 trustId,
        bytes32 key,
        uint8 reason,
        uint64 effectiveAt,
        bytes32 replacementKey
    ) internal returns (bytes32 revocationHash) {
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
        revocationHistoryByTrustIdKey[trustId][key].push(revocationHash);
        emit RevocationRecorded(revocationHash, trustId, key, reason, effectiveAt);
    }

    function _requireControllerOrAuthorizedSubmitter(bytes32 trustId, address caller) internal view {
        address controller = _controllerFor(trustId);
        if (controller != address(0)) {
            if (caller != controller) revert UnauthorizedRevocation(trustId, caller);
            return;
        }
        if (!authorizedSubmitters[caller]) revert UnauthorizedRevocation(trustId, caller);
    }

    function _controllerFor(bytes32 trustId) internal view returns (address) {
        if (trustIDRegistry == address(0)) return address(0);
        try ITrustIDRegistry(trustIDRegistry).getController(trustId) returns (address controller) {
            return controller;
        } catch {
            return address(0);
        }
    }
}
