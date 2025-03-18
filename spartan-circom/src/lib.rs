mod witness_reader;

use bincode::Error;
use libspartan::{Assignment, Instance, NIZK, NIZKGens};
use merlin::Transcript;

use crate::witness_reader::load_witness_from_bin_reader;

pub type F1 = curve25519_dalek::scalar::Scalar;

pub fn prove(circuit: &[u8], vars: &[u8], public_inputs: &[u8]) -> Result<Vec<u8>, Error> {
    let witness = load_witness_from_bin_reader::<F1, _>(vars).unwrap();
    let witness_bytes = witness
        .iter()
        .map(|w| w.to_bytes())
        .collect::<Vec<[u8; 32]>>();

    let assignment = Assignment::new(&witness_bytes).unwrap();
    let circuit: Instance = bincode::deserialize(circuit).unwrap();

    let num_cons = circuit.inst.get_num_cons();
    let num_vars = circuit.inst.get_num_vars();
    let num_inputs = circuit.inst.get_num_inputs();

    // produce public parameters
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    let mut input = Vec::new();
    for i in 0..num_inputs {
        input.push(public_inputs[(i * 32)..((i + 1) * 32)].try_into().unwrap());
    }
    let input = Assignment::new(&input).unwrap();

    let mut prover_transcript = Transcript::new(b"nizk_example");

    // produce a proof of satisfiability
    let proof = NIZK::prove(
        &circuit,
        assignment.clone(),
        &input,
        &gens,
        &mut prover_transcript,
    );

    Ok(bincode::serialize(&proof).unwrap())
}

pub fn verify(circuit: &[u8], proof: &[u8], public_input: &[u8]) -> Result<bool, Error> {
    let circuit: Instance = bincode::deserialize(circuit).unwrap();
    let proof: NIZK = bincode::deserialize(proof).unwrap();

    let num_cons = circuit.inst.get_num_cons();
    let num_vars = circuit.inst.get_num_vars();
    let num_inputs = circuit.inst.get_num_inputs();

    // produce public parameters
    let gens = NIZKGens::new(num_cons, num_vars, num_inputs);

    let mut inputs = Vec::new();
    for i in 0..num_inputs {
        inputs.push(public_input[(i * 32)..((i + 1) * 32)].try_into().unwrap());
    }

    let inputs = Assignment::new(&inputs).unwrap();

    let mut verifier_transcript = Transcript::new(b"nizk_example");

    let verified = proof
        .verify(&circuit, &inputs, &mut verifier_transcript, &gens)
        .is_ok();

    Ok(verified)
}

#[cfg(test)]
mod test {
    use ff::PrimeField;
    use std::path::PathBuf;

    use circuit_reader::load_as_spartan_inst;

    use super::{prove, verify};

    pub type F1 = curve25519_dalek::scalar::Scalar;

    #[test]
    fn test_prove_verify() {
        let r1cs_file = PathBuf::from("../circuits/multiplier2.r1cs");
        let witness_file = PathBuf::from("../circuits/witness.wtns");

        let witness = std::fs::read(witness_file).unwrap();

        let num_pub_inputs = 1;
        let spartan_inst = load_as_spartan_inst(r1cs_file, num_pub_inputs);
        let spartan_inst_bytes = bincode::serialize(&spartan_inst).unwrap();

        // let output_instance_file = PathBuf::from("spartan_inst.bin");
        // File::create(output_instance_file)
        //     .unwrap()
        //     .write_all(spartan_inst_bytes.as_slice())
        //     .unwrap();

        let public_inputs = [F1::from(3u64)]
            .iter()
            .map(|w| w.to_repr())
            .flatten()
            .collect::<Vec<u8>>();

        let proof = prove(&spartan_inst_bytes, &witness, &public_inputs).unwrap();
        let verified = verify(&spartan_inst_bytes, &proof, &public_inputs).unwrap();

        assert!(verified);

        let wrong_public_inputs = [F1::from(2u64)]
            .iter()
            .map(|w| w.to_repr())
            .flatten()
            .collect::<Vec<u8>>();

        let verified = verify(&spartan_inst_bytes, &proof, &wrong_public_inputs).unwrap();
        assert!(!verified);
    }
}
