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
