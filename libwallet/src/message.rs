//use rand::{Rng, thread_rng};
use crate::crypto::{from_hex, to_hex};
use crate::epic_util::secp::key::{PublicKey, SecretKey};
use crate::epic_util::secp::Secp256k1;
use core::num::NonZeroU32;

use crate::EpicboxAddress;
use crate::Error;

use serde::{Deserialize, Serialize};

use ring::aead;
use ring::pbkdf2;

use ring::aead::{BoundKey, Nonce, NonceSequence, NONCE_LEN};
use ring::error::Unspecified;
use ring::rand::{self, SecureRandom};

use std::convert::TryInto;

struct CounterNonceSequence(u64);

impl NonceSequence for CounterNonceSequence {
	// called once for each seal operation
	fn advance(&mut self) -> Result<Nonce, Unspecified> {
		let mut nonce_bytes = vec![0; NONCE_LEN];
		println!("nonce_len = {}", NONCE_LEN);
		let bytes = self.0.to_be_bytes();
		nonce_bytes[8..].copy_from_slice(&bytes);
		println!("nonce_bytes = {}", to_hex(nonce_bytes.clone()));

		self.0 += 1; // advance the counter
		aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
	}
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
	pub destination: EpicboxAddress,
	encrypted_message: String,
	salt: String,
	nonce: String,
}

impl EncryptedMessage {
	pub fn new(
		message: String,
		destination: &EpicboxAddress,
		receiver_public_key: &PublicKey,
		secret_key: &SecretKey,
	) -> Result<EncryptedMessage, Error> {
		let secp = Secp256k1::new();
		let mut common_secret = receiver_public_key.clone();
		common_secret
			.mul_assign(&secp, secret_key)
			.map_err(|_| Error::Encryption)?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let rng = rand::SystemRandom::new();
		let mut salt: [u8; 8] = [0; 8];
		rng.fill(&mut salt)?;
		let mut nonce_bytes: [u8; 8] = [0; 8];
		rng.fill(&mut nonce_bytes)?;
		let counter_val = u64::from_be_bytes(nonce_bytes);
		warn!("Counter val in encryption: {}", counter_val);
		//let nonce_val = thread_rng().gen::<[u8; 12]>();
		let nonce_sequence = CounterNonceSequence(counter_val);
		let mut nonce_sequence2 = CounterNonceSequence(counter_val);
		let mut key = [0; 32];
		pbkdf2::derive(
			pbkdf2::PBKDF2_HMAC_SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			common_secret_slice,
			&mut key,
		);
		let mut enc_bytes = message.as_bytes().to_vec();
		let suffix_len = aead::CHACHA20_POLY1305.tag_len();
		for _ in 0..suffix_len {
			enc_bytes.push(0);
		}
		let unbound_key =
			aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).map_err(|_| Error::Encryption)?;
		let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence);
		let aad = aead::Aad::<_>::empty();
		sealing_key
			.seal_in_place_append_tag(aad, &mut enc_bytes)
			.map_err(|_| Error::Encryption)?;

		Ok(EncryptedMessage {
			destination: destination.clone(),
			encrypted_message: to_hex(enc_bytes),
			salt: to_hex(salt.to_vec()),
			nonce: to_hex(nonce_sequence2.advance()?.as_ref().to_vec()),
		})
	}

	pub fn key(
		&self,
		sender_public_key: &PublicKey,
		secret_key: &SecretKey,
	) -> Result<[u8; 32], Error> {
		let salt = from_hex(self.salt.clone()).map_err(|_| Error::Decryption)?;

		let secp = Secp256k1::new();
		let mut common_secret = sender_public_key.clone();
		common_secret
			.mul_assign(&secp, secret_key)
			.map_err(|_| Error::Decryption)?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let mut key = [0; 32];
		pbkdf2::derive(
			pbkdf2::PBKDF2_HMAC_SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			common_secret_slice,
			&mut key,
		);

		Ok(key)
	}

	pub fn decrypt_with_key(&self, key: &[u8; 32]) -> Result<String, Error> {
		let mut encrypted_message =
			from_hex(self.encrypted_message.clone()).map_err(|_| Error::Decryption)?;
		let counter_vec = from_hex(self.nonce.clone()).map_err(|_| Error::Decryption)?;

		let unbound_key =
			aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key).map_err(|_| Error::Decryption)?;
		let counter_bytes: [u8; 8] = counter_vec.try_into().unwrap();
		let counter_val = u64::from_be_bytes(counter_bytes);
		warn!("CounterVal in decryption = {}", counter_val);
		let mut opening_key = aead::OpeningKey::new(unbound_key, CounterNonceSequence(counter_val));

		let aad = aead::Aad::<_>::empty();
		let decrypted_data = opening_key
			.open_in_place(aad, &mut encrypted_message)
			.map_err(|_| Error::Decryption)?;

		String::from_utf8(decrypted_data.to_vec()).map_err(|_| Error::Decryption.into())
	}
}
