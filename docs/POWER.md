# PoWER

Proof-of-Work-Enabled Relay (PoWER) is a [client puzzle protocol](https://en.wikipedia.org/wiki/Client_Puzzle_Protocol) meant to mitigate denial-of-service (DoS) attacks against Monero nodes caused by spam transactions. Monero nodes provide challenges that require clients/peers to provide a solution in order to relay high-input transactions.

This document contains instructions on how to follow the protocol.

- [Background](#background)
- [Definitions and notes](#definitions-and-notes)
- [Calculating PoWER challenges and solutions](#calculating-power-challenges-solutions)
	- [Challenge](#challenge)
		- [RPC](#rpc)
		- [P2P](#p2p)
	- [Solution](#solution)
		- [Equi-X](#equi-x)
		- [Difficulty](#difficulty)

## Background

Currently, verification of FCMP++ transactions with many inputs (e.g. 128-input transactions) can take several seconds on high-end hardware, while creation of invalid transactions is almost instantaneous. An attacker can exploit this asymmetry by spamming nodes with invalid transactions.

PoWER adds a computational cost by requiring Proof-of-Work (PoW) to be performed to enable relaying of high-input transactions.

## Definitions and notes

| Parameter                | Value          | Description |
|--------------------------|----------------|-------------|
| `INPUT_THRESHOLD`        | 8              | PoWER is required for transactions with input counts greater than this. Transaction with input counts less than or equal to this value can skip PoWER.
| `HEIGHT_WINDOW`          | 2              | Amount of block hashes that are valid as input for RPC PoWER challenge construction.
| `DIFFICULTY`             | 100            | Fixed value used for difficulty calculation.
| `PERSONALIZATION_STRING` | "Monero PoWER" | Personalization string used in PoWER related functions.

- Concatenation of bytes is denoted by `||`.
- All operations converting between integers and bytes are in little endian encoding.

## Calculating PoWER challenges and solutions

[Equi-X](https://github.com/tevador/equix) is the PoW algorithm used for PoWER challenges and solutions.

Equi-X is a CPU-friendly client-puzzle that takes in a ["challenge" (bytes)](https://github.com/tevador/equix/blob/c0b0d2bd210b870b3077f487a3705dfa7578208f/include/equix.h#L121) and outputs a [16-byte array "solution"](https://github.com/tevador/equix/blob/c0b0d2bd210b870b3077f487a3705dfa7578208f/include/equix.h#L28-L30).

### Challenge

Challenges are constructed differently depending on the interface. The below sections explain each interface.

#### RPC

For RPC (and ZMQ-RPC):

```
challenge = (PERSONALIZATION_STRING || tx_prefix_hash || recent_block_hash || nonce)
```

where:

- `PERSONALIZATION_STRING` is the string "Monero PoWER" as bytes.
- `tx_prefix_hash` is the transaction prefix hash of the transaction being relayed.
- `recent_block_hash` is a hash of a block within the last `HEIGHT_WINDOW` blocks.
- `nonce` is a 32-bit unsigned integer.

In the Monero codebase, this is the `create_challenge_rpc` function.

RPC endpoints that relay transactions contain fields where this data must be passed alongside the transaction.

Note that these fields are not required when any of the following are true:
- The transaction has less than or equal to `INPUT_THRESHOLD` inputs.
- The transaction orignates from a local/trusted source (unrestricted RPC, localhost, etc)

#### P2P

For P2P:

```
challenge = (PERSONALIZATION_STRING || seed || difficulty || nonce)
```

where:

- `PERSONALIZATION_STRING` is the string "Monero PoWER" as bytes.
- `seed` is a random 128-bit unsigned integer generated for each connection.
- `difficulty` is the 32-bit unsigned integer difficulty parameter the node requires to be used.
- `nonce` is a 32-bit unsigned integer.

In the Monero codebase, this is the `create_challenge_p2p` function.

`seed` and `difficulty` are provided by nodes in the initial P2P handshake message. Note that in the Monero codebase, `seed` is split into two 64-bit unsigned integers representing the low and high bits.

`nonce` should be adjusted until a valid Equi-X `solution` is produced that passes the difficulty formula with `difficulty`, then a `NOTIFY_POWER_SOLUTION` message should be sent containing the `solution` and `nonce`. This will enable high input transaction relay for that connection.

## Solution

A PoWER solution has 2 requirements:

1. It must be a valid Equi-X solution.
2. It must pass a difficulty formula.

The `nonce` in challenges should be adjusted until both 1 and 2 are satisfied.

### Equi-X

For 1, create an Equi-X `solution` for the `challenge` data created previously.

Note that `equix_solve` does not always create valid solutions. The `challenge` for
all interfaces contain a `nonce` field that should be adjusted until `equix_solve`
produces valid solution(s).

### Difficulty

For 2, a difficulty scalar must be created with:

```
scalar = to_le_bytes(blake2b_32(PERSONALIZATION_STRING || challenge || solution))
```

where:

- `to_le_bytes` converts a 4-byte array into a 32-bit unsigned integer in little endian order.
- `blake2b_32` is a `blake2b` hash set to a 32-bit output.
- `PERSONALIZATION_STRING` is the string "Monero PoWER".
- `challenge` are the full challenge bytes.
- `solution` are the Equi-X solution bytes.

In the Monero codebase, this is the `create_difficulty_scalar` function.

`scalar` must now pass the following difficulty formula:

```
scalar * difficulty <= MAX_UINT32
```

where:

- `difficulty` is either a constant (`DIFFICULTY`) for RPC, or the `difficulty` received from a peer for P2P.

In the Monero codebase, this is the `check_difficulty` function.