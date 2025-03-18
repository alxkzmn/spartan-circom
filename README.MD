# Spartan-Circom

Spartan is a zero-knowledge proof system using the R1CS arithmetization. See https://github.com/microsoft/Spartan for more information.

Circom is a popular DSL for writing ZK circuits that can be compiled into R1CS format. See https://docs.circom.io/ for more information.

This repository provides the tools to run Spartan using circuits written in Circom.

## Development

1. Install Circom with `curve25519` support

```shell
git clone https://github.com/DanTehrani/circom-secq
cd circom-secq && cargo build --release && cargo install --path circom
```

2. Build circuits

```shell
sh circuits/scripts/compile_circuit.sh
sh circuits/scripts/witgen.sh
```

## Credits

`circuit_reader` is adapted from https://github.com/personaelabs/spartan-ecdsa
