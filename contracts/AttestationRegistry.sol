// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title AttestationRegistry
/// @notice On-chain registry of issuer -> recipient attestations.
/// @dev Each attestation is keyed by a uid derived from its contents plus a
///      global counter, so two identical attestations in the same block get
///      different uids. Records are immutable except for revocation, which
///      only the original issuer can perform. An attestation may carry an
///      expiry time; after it passes, the record still exists but is no
///      longer valid.
contract AttestationRegistry {
    struct Attestation {
        address issuer;
        address recipient;
        string data;
        uint64 blockNumber;
        uint64 timestamp;
        uint64 expiresAt; // 0 = never expires
        bool revoked;
    }

    event AttestationCreated(
        bytes32 indexed uid,
        address indexed issuer,
        address indexed recipient,
        string data,
        uint64 expiresAt
    );
    event AttestationRevoked(bytes32 indexed uid, address indexed issuer);

    error ZeroRecipient();
    error ExpiryInPast(uint64 expiresAt, uint256 nowTimestamp);
    error AttestationNotFound(bytes32 uid);
    error NotIssuer(bytes32 uid, address caller);
    error AlreadyRevoked(bytes32 uid);

    mapping(bytes32 => Attestation) private _attestations;

    /// @notice Total attestations ever created (revoked ones included).
    uint256 public attestationCount;

    /// @param expiresAt Unix time after which the attestation is no longer valid; 0 for never.
    function createAttestation(address recipient, string calldata data, uint64 expiresAt)
        external
        returns (bytes32 uid)
    {
        if (recipient == address(0)) revert ZeroRecipient();
        if (expiresAt != 0 && expiresAt <= block.timestamp) revert ExpiryInPast(expiresAt, block.timestamp);

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
            expiresAt: expiresAt,
            revoked: false
        });

        emit AttestationCreated(uid, msg.sender, recipient, data, expiresAt);
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

    /// @notice True when the attestation exists, is not revoked and has not expired.
    function isValid(bytes32 uid) external view returns (bool) {
        Attestation storage a = _attestations[uid];
        return a.issuer != address(0) && !a.revoked && (a.expiresAt == 0 || block.timestamp < a.expiresAt);
    }

    function getAttestation(bytes32 uid) external view returns (Attestation memory) {
        Attestation memory a = _attestations[uid];
        if (a.issuer == address(0)) revert AttestationNotFound(uid);
        return a;
    }
}
