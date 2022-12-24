pub use curv::BigInt;
use serde::{Deserialize, Serialize};

pub const SECURITY_BITS: usize = 256;

pub mod party_one;
pub mod party_two;

#[cfg(test)]
mod test;
mod utilities;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub s: BigInt,
    pub r: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedSignature {
    pub sd_prime: BigInt,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
    Phase5BadSum,
    Phase6Error,
}

