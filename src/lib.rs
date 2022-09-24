pub use curv::BigInt;
use serde::{Deserialize, Serialize};

const SECURITY_BITS: usize = 256;

pub mod party_one;
pub mod party_two;

#[cfg(test)]
mod test;


#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: BigInt,
    pub r: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedSignature {
    pub sd_prime: BigInt,
}

