use crate::{party_one, party_two};
use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};
use curv::BigInt;

#[test]
fn test_two_party_sign() {
    // assume party1 and party2 engaged with KeyGen in the past resulting in
    // party1 owning private share and paillier key-pair
    // party2 owning private share and paillier encryption of party1 share
    let (_, _comm_witness, keypair_party1) = party_one::keygen::first_message();
    let (party_two_private_share_gen, keypair_party2) = party_two::keygen::first_message();

    let keypair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&keypair_party1);

    // generating adaptor witness (y)
    let y = Scalar::<Secp256k1>::random();

    // creating the ephemeral private shares:
    let (p2_presign_msg1, p2_presign_local1) =
        party_two::sign::first_message(&y);
    let (eph_party_one_first_message, r1) = party_one::sign::first_message();


    let message = BigInt::from(1234);
    let partial_sig = party_two::sign::second_message(
        p2_presign_local1.k2_commit,
        &eph_party_one_first_message,
        &keypair.ek,
        &keypair.encrypted_share,
        &keypair_party2,
        &p2_presign_local1.k2_pair,
        &eph_party_one_first_message.public_share,
        &p2_presign_local1.k3_pair,
        &message,
    ).unwrap();

    let _ = party_one::sign::verify_commitments_and_dlog_proof(
        &p2_presign_msg1,
        &partial_sig,
    )
        .expect("failed to verify commitments and DLog proof");

    let party1_private = party_one::Party1Private::set_private_key(&keypair_party1, &keypair);

    let encrypted_sig = party_one::sign::second_message(
        &party1_private,
        &keypair_party1.public_share,
        &partial_sig.c3,
        &r1,
        &partial_sig.comm_witness.public_share,
        &p2_presign_local1.k3_pair.public_share,
        &message,
    );
    let signature = party_two::sign::decrypt_signature(&encrypted_sig, &y, &r1.public_share, &p2_presign_local1.k3_pair);

    let pubkey =
        party_one::keygen::compute_pubkey(&keypair_party1, &party_two_private_share_gen.public_share);
    party_one::verify_signature(&signature, &pubkey, &message).expect("Invalid signature");

    let y_check = party_one::sign::recover_witness(encrypted_sig, &signature);

    assert_eq!(y_check, y);
}
