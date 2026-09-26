// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AttestationRegistry
/// @notice On-chain registry of issuer -> recipient attestations.
/// @dev Each attestation is keyed by a uid derived from its contents plus a
///      global counter, so two identical attestations in the same block get
///      different uids. Records are immutable except for revocation, which
///      only the original issuer can perform.
contract AttestationRegistry {
    struct Attestation {
        address issuer;
        address recipient;
        string data;
        uint64 blockNumber;
        uint64 timestamp;
        bool revoked;
    }

    event AttestationCreated(
        bytes32 indexed uid,
        address indexed issuer,
        address indexed recipient,
        string data,
        uint256 blockNumber
    );
    event AttestationRevoked(bytes32 indexed uid, address indexed issuer);

    error ZeroRecipient();
    error AttestationNotFound(bytes32 uid);
    error NotIssuer(bytes32 uid, address caller);
    error AlreadyRevoked(bytes32 uid);

    mapping(bytes32 => Attestation) private _attestations;

    /// @notice Total attestations ever created (revoked ones included).
    uint256 public attestationCount;

    function createAttestation(address recipient, string calldata data) external returns (bytes32 uid) {
        if (recipient == address(0)) revert ZeroRecipient();

        uid = keccak256(abi.encode(msg.sender, recipient, data, block.number, attestationCount));
        unchecked {
            attestationCount += 1;
        }

        _attestations[uid] = Attestation({
            issuer: msg.sender,
            recipient: recipient,
            data: data,
            blockNumber: uint64(block.number),
            timestamp: uint64(block.timestamp),
            revoked: false
        });

        emit AttestationCreated(uid, msg.sender, recipient, data, block.number);
    }

    function revokeAttestation(bytes32 uid) external {
        Attestation storage a = _attestations[uid];
        if (a.issuer == address(0)) revert AttestationNotFound(uid);
        if (a.issuer != msg.sender) revert NotIssuer(uid, msg.sender);
        if (a.revoked) revert AlreadyRevoked(uid);

        a.revoked = true;
        emit AttestationRevoked(uid, msg.sender);
    }

    function exists(bytes32 uid) external view returns (bool) {
        return _attestations[uid].issuer != address(0);
    }

    function getAttestation(bytes32 uid) external view returns (Attestation memory) {
        Attestation memory a = _attestations[uid];
        if (a.issuer == address(0)) revert AttestationNotFound(uid);
        return a;
    }
}
