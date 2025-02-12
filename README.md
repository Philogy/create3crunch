# Create3 Crunch

> A Rust program for finding salts that create gas-efficient Ethereum addresses via CREATE3.

Unlike normal CREATE3, this miner allows you to test for multiple nonces in the "deploy proxy"
contract (the standard contract that gets deployed with create2 that eventually deploys your contract).
This allows the miner to approach CREATE2 in mining speeds as checking different nonces ammortizes
the initial fixed cost of computing the deploy proxy's address.

> [!CAUTION]
> Non-default (nonce = 1) nonces is not supported by the majority of CREATE3 libraries, set the
> max-nonce to `1` if you only want to search with `nonce = 1`, note this will degrade the
> performance of the miner.

## Installation Instructions

1. Install Rust
2. Clone repo
3. Build with `cargo build --release` (performance is mostly GPU bound so a debug build is probably
   fine too).
4. Run with `./target/release/create3crunch`.

## Usage

TODO, but in the meantime check the available options using `-h` or `--help`.

## POST results

You can specify a `--post-url` argument. Results will be POSTed to this url.

### Custom addresses

You can specify custom addresses. The miner will also accept capitalization and do a checksum ckeck. Use `x` for wildcards. You can also define bits by adding `[x01x]` into the pattern. This only works for full nibbles.
Specify multiple patterns my adding multiple `--patern` argumetns.

Example command:

```
./target/release/create3crunch \
    --factory 0x00000000000000000000000000000000d53c15aa \
    --owner 0x2c8B14A270eb00000000000000000000aBF15BF8 \
    --init-code-hash 0x1decbcf04b355d500000000000000000000000000000000cb9f7f8165e2095c3 \
    --gpu-device 0 \
    --pattern "0xaBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
    --pattern "0xCexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx[xx001010]" \
    --output-file mined0.txt --case-sensitive
```
