// Package adapted from the spartan-ecdsa project:
// https://github.com/personaelabs/spartan-ecdsa

mod circom_reader;

use circom_reader::{load_r1cs_from_bin_file, R1CS};
use curve25519_dalek::RistrettoPoint;
use ff::PrimeField;
use group::GroupEncoding;
use libspartan::Instance;
use std::path::PathBuf;

pub fn load_as_spartan_inst(circuit_file: PathBuf, num_pub_inputs: usize) -> Instance {
    let (r1cs, _) = load_r1cs_from_bin_file::<RistrettoPoint>(&circuit_file);
    convert_to_spartan_r1cs(&r1cs, num_pub_inputs)
}

#[allow(non_snake_case)]
pub fn convert_to_spartan_r1cs<F: PrimeField<Repr = <RistrettoPoint as GroupEncoding>::Repr>>(
    r1cs: &R1CS<F>,
    num_pub_inputs: usize,
) -> Instance {
    let num_cons = r1cs.constraints.len();
    let num_vars = r1cs.num_variables;
    let num_inputs = num_pub_inputs;

    let mut A = vec![];
    let mut B = vec![];
    let mut C = vec![];

    for (i, constraint) in r1cs.constraints.iter().enumerate() {
        let (a, b, c) = constraint;

        for (j, coeff) in a.iter() {
            let bytes: [u8; 32] = coeff.to_repr();

            A.push((i, *j, bytes));
        }

        for (j, coeff) in b.iter() {
            let bytes: [u8; 32] = coeff.to_repr();
            B.push((i, *j, bytes));
        }

        for (j, coeff) in c.iter() {
            let bytes: [u8; 32] = coeff.to_repr();
            C.push((i, *j, bytes));
        }
    }

    let inst = Instance::new(
        num_cons,
        num_vars,
        num_inputs,
        A.as_slice(),
        B.as_slice(),
        C.as_slice(),
    )
    .unwrap();

    inst
}
