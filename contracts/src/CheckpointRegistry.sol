// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CheckpointRegistry {
    error NotOwner();
    error UnauthorizedSubmitter(address submitter);
    error UnauthorizedRelay(bytes32 relayId);
    error EmptyRelaySignature();
    error InvalidRelaySignature(bytes32 relayId, address recoveredSigner);
    error CheckpointConflict(bytes32 existingCheckpointHash, bytes32 newCheckpointHash);

    struct CheckpointInput {
        uint64 epochStartMs;
        uint32 epochDurationMs;
        bytes32 shard;
        bytes32 eventRoot;
        bytes32 receiptRoot;
        bytes32 attestationRoot;
        bytes32 revocationRoot;
        uint64 eventCount;
        uint64 receiptCount;
        bytes32 previousCheckpoint;
        bytes32 relayId;
        bytes32 settlementBackend;
    }

    struct Checkpoint {
        uint64 epochStartMs;
        uint32 epochDurationMs;
        bytes32 shard;
        bytes32 eventRoot;
        bytes32 receiptRoot;
        bytes32 attestationRoot;
        bytes32 revocationRoot;
        uint64 eventCount;
        uint64 receiptCount;
        bytes32 previousCheckpoint;
        bytes32 relayId;
        bytes32 settlementBackend;
        uint64 submittedAt;
    }

    address public owner;
    mapping(address => bool) public authorizedSubmitters;
    mapping(bytes32 => bool) public authorizedRelays;
    mapping(bytes32 => address) public relaySigners;
    mapping(bytes32 => Checkpoint) public checkpointsByHash;
    mapping(bytes32 => bytes32) public checkpointHashByEpochShard;

    event SubmitterAuthorizationUpdated(address indexed submitter, bool authorized);
    event RelayAuthorizationUpdated(bytes32 indexed relayId, bool authorized);
    event RelaySignerUpdated(bytes32 indexed relayId, address indexed signer);
    event CheckpointSubmitted(
        bytes32 indexed checkpointHash,
        uint64 indexed epochStartMs,
        bytes32 indexed shard,
        bytes32 eventRoot,
        address submitter
    );
    event CheckpointAlreadySubmitted(bytes32 indexed checkpointHash, uint64 indexed epochStartMs, bytes32 indexed shard);

    constructor() {
        owner = msg.sender;
        authorizedSubmitters[msg.sender] = true;
        emit SubmitterAuthorizationUpdated(msg.sender, true);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function setAuthorizedSubmitter(address submitter, bool authorized) external onlyOwner {
        authorizedSubmitters[submitter] = authorized;
        emit SubmitterAuthorizationUpdated(submitter, authorized);
    }

    function setAuthorizedRelay(bytes32 relayId, bool authorized) external onlyOwner {
        authorizedRelays[relayId] = authorized;
        emit RelayAuthorizationUpdated(relayId, authorized);
    }

    function setRelaySigner(bytes32 relayId, address signer) external onlyOwner {
        relaySigners[relayId] = signer;
        emit RelaySignerUpdated(relayId, signer);
    }

    function submitCheckpoint(
        CheckpointInput calldata input,
        bytes calldata relaySignature
    ) external returns (bytes32 checkpointHash) {
        if (!authorizedSubmitters[msg.sender]) revert UnauthorizedSubmitter(msg.sender);
        if (!authorizedRelays[input.relayId]) revert UnauthorizedRelay(input.relayId);
        if (relaySignature.length == 0) revert EmptyRelaySignature();

        bytes32 key = epochShardKey(input.epochStartMs, input.shard);
        checkpointHash = hashCheckpoint(input);
        address recoveredSigner = recoverRelaySigner(checkpointHash, relaySignature);
        if (relaySigners[input.relayId] == address(0) || relaySigners[input.relayId] != recoveredSigner) {
            revert InvalidRelaySignature(input.relayId, recoveredSigner);
        }
        bytes32 existing = checkpointHashByEpochShard[key];

        if (existing != bytes32(0)) {
            if (existing != checkpointHash) {
                revert CheckpointConflict(existing, checkpointHash);
            }
            emit CheckpointAlreadySubmitted(checkpointHash, input.epochStartMs, input.shard);
            return checkpointHash;
        }

        checkpointsByHash[checkpointHash] = Checkpoint({
            epochStartMs: input.epochStartMs,
            epochDurationMs: input.epochDurationMs,
            shard: input.shard,
            eventRoot: input.eventRoot,
            receiptRoot: input.receiptRoot,
            attestationRoot: input.attestationRoot,
            revocationRoot: input.revocationRoot,
            eventCount: input.eventCount,
            receiptCount: input.receiptCount,
            previousCheckpoint: input.previousCheckpoint,
            relayId: input.relayId,
            settlementBackend: input.settlementBackend,
            submittedAt: uint64(block.timestamp)
        });
        checkpointHashByEpochShard[key] = checkpointHash;

        emit CheckpointSubmitted(checkpointHash, input.epochStartMs, input.shard, input.eventRoot, msg.sender);
    }

    function getCheckpoint(bytes32 checkpointHash) external view returns (Checkpoint memory) {
        return checkpointsByHash[checkpointHash];
    }

    function getCheckpointByEpochShard(uint64 epochStartMs, bytes32 shard) external view returns (Checkpoint memory) {
        bytes32 checkpointHash = checkpointHashByEpochShard[epochShardKey(epochStartMs, shard)];
        return checkpointsByHash[checkpointHash];
    }

    function hasCheckpoint(uint64 epochStartMs, bytes32 shard) external view returns (bool) {
        return checkpointHashByEpochShard[epochShardKey(epochStartMs, shard)] != bytes32(0);
    }

    function epochShardKey(uint64 epochStartMs, bytes32 shard) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(epochStartMs, shard));
    }

    function hashCheckpoint(CheckpointInput calldata input) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                input.epochStartMs,
                input.epochDurationMs,
                input.shard,
                input.eventRoot,
                input.receiptRoot,
                input.attestationRoot,
                input.revocationRoot,
                input.eventCount,
                input.receiptCount,
                input.previousCheckpoint,
                input.relayId,
                input.settlementBackend
            )
        );
    }

    function relayMessageHash(bytes32 checkpointHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", checkpointHash));
    }

    function recoverRelaySigner(bytes32 checkpointHash, bytes calldata signature) public pure returns (address) {
        if (signature.length != 65) {
            return address(0);
        }

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            return address(0);
        }
        return ecrecover(relayMessageHash(checkpointHash), v, r, s);
    }
}
