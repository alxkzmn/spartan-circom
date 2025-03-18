use bincode::Error;
use byteorder::{LittleEndian, ReadBytesExt};
use ff::PrimeField;
use std::io::Read;

// Copied from Nova Scotia
pub fn read_field<R: Read, Fr: PrimeField>(mut reader: R) -> Result<Fr, Error> {
    let mut repr = Fr::ZERO.to_repr();
    for digit in repr.as_mut().iter_mut() {
        // TODO: may need to reverse order?
        *digit = reader.read_u8()?;
    }
    let fr = Fr::from_repr(repr).unwrap();
    Ok(fr)
}

pub fn load_witness_from_bin_reader<Fr: PrimeField, R: Read>(
    mut reader: R,
) -> Result<Vec<Fr>, Error> {
    let mut wtns_header = [0u8; 4];
    reader.read_exact(&mut wtns_header)?;
    if wtns_header != [119, 116, 110, 115] {
        // ruby -e 'p "wtns".bytes' => [119, 116, 110, 115]
        panic!("invalid file header");
    }
    let version = reader.read_u32::<LittleEndian>()?;
    // println!("wtns version {}", version);
    if version > 2 {
        panic!("unsupported file version");
    }
    let num_sections = reader.read_u32::<LittleEndian>()?;
    if num_sections != 2 {
        panic!("invalid num sections");
    }
    // read the first section
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 1 {
        panic!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != 4 + 32 + 4 {
        panic!("invalid section len")
    }
    let field_size = reader.read_u32::<LittleEndian>()?;
    if field_size != 32 {
        panic!("invalid field byte size");
    }
    let mut prime = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime)?;
    // if prime != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430") {
    //     bail!("invalid curve prime {:?}", prime);
    // }
    let witness_len = reader.read_u32::<LittleEndian>()?;
    // println!("witness len {}", witness_len);
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 2 {
        panic!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != (witness_len * field_size) as u64 {
        panic!("invalid witness section size {}", sec_size);
    }
    let mut result = Vec::with_capacity(witness_len as usize);
    for _ in 0..witness_len {
        result.push(read_field::<&mut R, Fr>(&mut reader)?);
    }
    Ok(result)
}
