
use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives::proofs::ProofError;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use paillier::Paillier;
use paillier::{Add, Encrypt, Mul};
use paillier::{EncryptionKey, RawCiphertext, RawPlaintext};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zk_paillier::zkproofs::{IncorrectProof, NiCorrectKeyProof};

use crate::party_one::sign::PreSignMsg1 as Party1SignMsg1;
use crate::party_one::keygen::KeyGenMsg1 as Party1KeyGenMsg1;
use crate::party_one::keygen::KeyGenMsg2 as Party1KeyGenMsg2;
use crate::SECURITY_BITS;
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};

use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackStatement;
use thiserror::Error;
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

#[derive(Error, Debug)]
pub enum PartyTwoError {
    #[error("party two pdl verify failed (lindell 2017)")]
    PdlVerify,
}

const PAILLIER_KEY_SIZE: usize = 2048;
//****************** Begin: Party Two structs ******************//

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcKeyPair {
    pub public_share: Point<Secp256k1>,
    secret_share: Scalar<Secp256k1>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaillierPublic {
    pub ek: EncryptionKey,
    pub encrypted_secret_share: BigInt,
}

#[derive(Serialize, Deserialize)]
pub struct Party2Private {
    x2: Scalar<Secp256k1>,
}
#[derive(Debug)]
pub struct PDLchallenge {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
    a: BigInt,
    b: BigInt,
    blindness: BigInt,
    q_tag: Point<Secp256k1>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLFirstMessage {
    pub c_tag: BigInt,
    pub c_tag_tag: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLdecommit {
    pub a: BigInt,
    pub b: BigInt,
    pub blindness: BigInt,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PDLSecondMessage {
    pub decommit: PDLdecommit,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EccKeyPair {
    pub public_share: Point<Secp256k1>,
    secret_share: Scalar<Secp256k1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DlogCommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: Point<Secp256k1>,
    pub d_log_proof: ECDDHProof<Secp256k1, Sha256>,
    pub c: Point<Secp256k1>, //c = secret_share * base_point2
}

//****************** End: Party Two structs ******************//

pub mod keygen {
    use super::*;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct KeyGenMsg1 {
        pub d_log_proof: DLogProof<Secp256k1, Sha256>,
        pub public_share: Point<Secp256k1>,
    }

    pub fn first_message() -> (KeyGenMsg1, EcKeyPair) {
        let base = Point::generator();
        let secret_share = Scalar::<Secp256k1>::random();
        let public_share = base * &secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };

        (
            KeyGenMsg1 {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }

    pub fn second_message(
        party_one_first_message: &Party1KeyGenMsg1,
        party_one_second_message: &Party1KeyGenMsg2,
        party_one_second_message_salt: &[u8]
    ) -> Result<PaillierPublic, ()> {
        let paillier_encryption_key = party_one_second_message.ek.clone();
        let paillier_encrypted_share = party_one_second_message.c_key.clone();

        let party_two_second_message =
            verify_commitments_and_dlog_proof(
                &party_one_first_message,
                &party_one_second_message,
            );

        let party_two_paillier = PaillierPublic {
            ek: paillier_encryption_key.clone(),
            encrypted_secret_share: paillier_encrypted_share.clone(),
        };

        let pdl_verify = PaillierPublic::pdl_verify(
            &party_one_second_message.composite_dlog_proof,
            &party_one_second_message.pdl_statement,
            &party_one_second_message.pdl_proof,
            &party_two_paillier,
            &party_one_second_message
                .comm_witness
                .public_share,
        );

        let correct_key_verify = party_one_second_message
            .correct_key_proof
            .verify(&party_two_paillier.ek, party_one_second_message_salt);

        match pdl_verify {
            Ok(_proof) => match correct_key_verify {
                Ok(_proof) => match party_two_second_message {
                    Ok(_) => Ok(party_two_paillier),
                    Err(_verify_com_and_dlog_party_one) => Err(()),
                },
                Err(_correct_key_error) => Err(()),
            },
            Err(_pdl_error) => Err(()),
        }
    }

    pub fn create_with_fixed_secret_share(
        secret_share: Scalar<Secp256k1>,
    ) -> (KeyGenMsg1, EcKeyPair) {
        let base = Point::generator();
        let public_share = base * &secret_share;
        let d_log_proof = DLogProof::prove(&secret_share);
        let ec_key_pair = EcKeyPair {
            public_share: public_share.clone(),
            secret_share,
        };
        (
            KeyGenMsg1 {
                d_log_proof,
                public_share,
            },
            ec_key_pair,
        )
    }

    pub fn verify_commitments_and_dlog_proof(
        party_one_first_message: &Party1KeyGenMsg1,
        party_one_second_message: &Party1KeyGenMsg2,
    ) -> Result<(), ProofError> {
        let party_one_pk_commitment = &party_one_first_message.pk_commitment;
        let party_one_zk_pok_commitment = &party_one_first_message.zk_pok_commitment;
        let party_one_zk_pok_blind_factor =
            &party_one_second_message.comm_witness.zk_pok_blind_factor;
        let party_one_public_share = &party_one_second_message.comm_witness.public_share;
        let party_one_pk_commitment_blind_factor = &party_one_second_message
            .comm_witness
            .pk_commitment_blind_factor;
        let party_one_d_log_proof = &party_one_second_message.comm_witness.d_log_proof;

        let mut flag = true;
        if party_one_pk_commitment
            != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(party_one_public_share.to_bytes(true).as_ref()),
            party_one_pk_commitment_blind_factor,
        )
        {
            flag = false
        }
        if party_one_zk_pok_commitment
            != &HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(
                party_one_d_log_proof
                    .pk_t_rand_commitment
                    .to_bytes(true)
                    .as_ref(),
            ),
            party_one_zk_pok_blind_factor,
        )
        {
            flag = false
        }

        if !flag {
            return Err(ProofError);
        }

        DLogProof::verify(party_one_d_log_proof)?;
        Ok(())
    }

    pub fn compute_pubkey(
        local_share: &EcKeyPair,
        other_share_public_share: &Point<Secp256k1>,
    ) -> Point<Secp256k1> {
        other_share_public_share * &local_share.secret_share
    }
}



impl Party2Private {
    pub fn set_private_key(ec_key: &EcKeyPair) -> Party2Private {
        Party2Private {
            x2: ec_key.secret_share.clone(),
        }
    }

    pub fn update_private_key(party_two_private: &Party2Private, factor: &BigInt) -> Party2Private {
        let factor_fe = Scalar::<Secp256k1>::from(factor);
        Party2Private {
            x2: &party_two_private.x2 * &factor_fe,
        }
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: usize,
        num_of_segments: usize,
        pub_ke_y: &Point<Secp256k1>,
        g: &Point<Secp256k1>,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.x2, &segment_size, num_of_segments, pub_ke_y, g)
    }

    // used to transform lindell master key to gg18 master key
    pub fn to_mta_message_b(
        &self,
        ek: &EncryptionKey,
        ciphertext: &BigInt,
    ) -> (MessageB, Scalar<Secp256k1>) {
        let message_a = MessageA {
            c: ciphertext.clone(),
            range_proofs: vec![],
        };
        let (a, b, _, _) = MessageB::b(&self.x2, ek, message_a, &[]).unwrap();
        (a, b)
    }
}

impl PaillierPublic {
    pub fn pdl_verify(
        composite_dlog_proof: &CompositeDLogProof,
        pdl_w_slack_statement: &PDLwSlackStatement,
        pdl_w_slack_proof: &PDLwSlackProof,
        paillier_public: &PaillierPublic,
        q1: &Point<Secp256k1>,
    ) -> Result<(), PartyTwoError> {
        if pdl_w_slack_statement.ek != paillier_public.ek
            || pdl_w_slack_statement.ciphertext != paillier_public.encrypted_secret_share
            || &pdl_w_slack_statement.Q != q1
        {
            return Err(PartyTwoError::PdlVerify);
        }
        let dlog_statement = DLogStatement {
            N: pdl_w_slack_statement.N_tilde.clone(),
            g: pdl_w_slack_statement.h1.clone(),
            ni: pdl_w_slack_statement.h2.clone(),
        };
        if composite_dlog_proof.verify(&dlog_statement).is_ok()
            && pdl_w_slack_proof.verify(pdl_w_slack_statement).is_ok()
        {
            Ok(())
        } else {
            Err(PartyTwoError::PdlVerify)
        }
    }

    pub fn verify_ni_proof_correct_key(
        proof: NiCorrectKeyProof,
        ek: &EncryptionKey,
    ) -> Result<(), IncorrectProof> {
        //
        if ek.n.bit_length() < PAILLIER_KEY_SIZE - 1 {
            return Err(IncorrectProof);
        };
        proof.verify(ek, zk_paillier::zkproofs::SALT_STRING)
    }
}

pub mod sign {
    use crate::EncryptedSignature;
    use super::*;

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct PreSignMsg1 {
        pub pk_commitment: BigInt,
        pub zk_pok_commitment: BigInt,
    }

    // #[derive(Debug, Serialize, Deserialize)]
    // pub struct PreSignMsg2 {
    //     pub comm_witness: DlogCommWitness,
    // }

    pub struct PreSignRound1Local {
        pub k2_pair: EccKeyPair,
        pub k3_pair: EccKeyPair,
        pub k2_commit: DlogCommWitness,
        pub k3_commit: DlogCommWitness,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct PreSignMsg2 {
        pub c3: BigInt,
        pub comm_witness: DlogCommWitness,
        pub k3_pair: EccKeyPair, // todo: ensure that it's secure to share k3 scalar
        pub message: BigInt
    }

    // P2's first massage (phase 2)
    pub fn first_message(witness: &Scalar<Secp256k1>) -> (PreSignMsg1, PreSignRound1Local) {
        let k2 = Scalar::<Secp256k1>::random();
        let y = witness;
        let k3 = y*&k2;

        let (msg, k2_commit, k2_pair) = commit_to_dlog(&k2);

        let (_, k3_commit, k3_pair) = commit_to_dlog(&k3);

        let local = PreSignRound1Local {
            k2_pair,
            k3_pair,
            k2_commit,
            k3_commit
        };

        return (msg, local)
    }

    fn commit_to_dlog(x: &Scalar<Secp256k1>) -> (PreSignMsg1, DlogCommWitness, EccKeyPair) {
        let g = Point::generator();
        let h = Point::<Secp256k1>::base_point2();

        let x_pub = g * x;

        let c = h * x;
        let w = ECDDHWitness {
            x: x.clone(),
        };
        let delta = ECDDHStatement {
            g1: g.to_point(),
            h1: x_pub.clone(),
            g2: h.clone(),
            h2: c.clone(),
        };
        let d_log_proof = ECDDHProof::prove(&w, &delta);

        // we use hash based commitment
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &BigInt::from_bytes(x_pub.to_bytes(true).as_ref()),
                &pk_commitment_blind_factor,
            );

        let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment =
            HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                &Sha256::new()
                    .chain_points([&d_log_proof.a1, &d_log_proof.a2])
                    .result_bigint(),
                &zk_pok_blind_factor,
            );

        let ec_key_pair = EccKeyPair {
            public_share: x_pub,
            secret_share: x.clone(),
        };

        (
            PreSignMsg1 {
                pk_commitment,
                zk_pok_commitment,
            },
            DlogCommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share.clone(),
                d_log_proof,
                c,
            },
            ec_key_pair,
        )
    }

    fn verify_and_decommit(
        party_one_first_message: &Party1SignMsg1,
    ) -> Result<(), ProofError> {
        let delta = ECDDHStatement {
            g1: Point::generator().to_point(),
            h1: party_one_first_message.public_share.clone(),
            g2: Point::<Secp256k1>::base_point2().clone(),
            h2: party_one_first_message.c.clone(),
        };
        party_one_first_message.d_log_proof.verify(&delta)
    }

    // P2's second message (phase 4)
    pub fn second_message(
        k2: DlogCommWitness,
        party_one_first_message: &Party1SignMsg1,
        ek: &EncryptionKey,
        encrypted_secret_share: &BigInt,
        local_share: &EcKeyPair,
        ephemeral_local_share: &EccKeyPair,
        ephemeral_other_public_share: &Point<Secp256k1>,
        k3_pair: &EccKeyPair,
        message: &BigInt,
    ) -> Result<PreSignMsg2, ProofError> {
        verify_and_decommit(party_one_first_message)?;

        let local_share = Party2Private::set_private_key(local_share);

        let q = Scalar::<Secp256k1>::group_order();
        //compute r = r3* R1
        let r = ephemeral_other_public_share * &k3_pair.secret_share;

        let rx = r.x_coord().unwrap().mod_floor(q);
        let rho = BigInt::sample_below(&q.pow(2));
        let k2_inv = BigInt::mod_inv(&ephemeral_local_share.secret_share.to_bigint(), q).unwrap();
        let partial_sig = rho * q + BigInt::mod_mul(&k2_inv, message, q);

        let c1 = Paillier::encrypt(ek, RawPlaintext::from(partial_sig));
        let v = BigInt::mod_mul(
            &k2_inv,
            &BigInt::mod_mul(&rx, &local_share.x2.to_bigint(), q),
            q,
        );
        let c2 = Paillier::mul(
            ek,
            RawCiphertext::from(encrypted_secret_share.clone()),
            RawPlaintext::from(v),
        );

        Ok(PreSignMsg2 {
            c3: Paillier::add(ek, c2, c1).0.into_owned(),
            comm_witness: k2,
            k3_pair: k3_pair.clone(),
            message: message.clone()
        })
    }

    // P2 generate output (phase 6)
    pub fn decrypt_signature(
        adaptor: &crate::EncryptedSignature,
        decryption_key: &Scalar<Secp256k1>,
        r1_pub: &Point<Secp256k1>,
        k3: &EccKeyPair,
    ) -> crate::Signature {
        let y = decryption_key;
        let y_inv = y.invert().unwrap();
        // compute s = s'' * y^-1
        let s = y_inv * Scalar::from_bigint(&adaptor.sd_prime);
        let s = s.to_bigint();

        let r = r1_pub * &k3.secret_share;
        let r_x = r.x_coord().unwrap();

        crate::Signature {
            s,
            r: r_x
        }
    }
}

