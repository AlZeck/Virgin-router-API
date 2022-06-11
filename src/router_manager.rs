use data_encoding::HEXLOWER;
use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::{pbkdf2, rand};
use serde_json::json;
use std::num::NonZeroU32;

use aes::Aes128;
use ccm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use ccm::{
  consts::{U16, U8},
  Ccm,
};

pub type AesCcm128 = Ccm<Aes128, U16, U8>;

fn get_encrypted_login_payload(password: &str) -> Result<String, Unspecified> {
  let n_iter = NonZeroU32::new(1_000).unwrap();
  let rng = rand::SystemRandom::new();

  let mut salt = [0u8; 8];
  rng.fill(&mut salt)?;

  let mut iv = [0u8; 8];
  rng.fill(&mut iv)?;
  println!("Salt: {}", HEXLOWER.encode(&salt));
  println!("IV: {}", HEXLOWER.encode(&iv));

  let mut pbkdf2_hash = [0u8; 16];

  pbkdf2::derive(
    pbkdf2::PBKDF2_HMAC_SHA256,
    n_iter,
    &salt,
    password.as_bytes(),
    &mut pbkdf2_hash,
  );

  println!("PBKDF2 hash: {}", HEXLOWER.encode(&pbkdf2_hash));

  let json = json!( {
    "csrfNonce": "undefined",
    "newPassword": password,
    "oldPassword": password,
    "ChangePassword": "false",
    "authData": "encryptData",
    "iv": HEXLOWER.encode(&iv),
    "salt": HEXLOWER.encode(&salt),
  });

  let plaintext = match serde_json::to_vec(&json) {
    Ok(s) => s,
    Err(e) => panic!("Error converting to string: {}", e),
  };
  let aad = "encryptData".as_bytes().to_vec();

  let key: &GenericArray<u8, U16> = GenericArray::from_slice(&pbkdf2_hash);
  let cypher = AesCcm128::new(key);
  let nonce: &GenericArray<u8, U8> = GenericArray::from_slice(&iv);
  let cyphertext = match cypher.encrypt(
    nonce,
    Payload {
      aad: &aad,
      msg: &plaintext,
    },
  ) {
    Ok(ct) => ct,
    Err(_) => {
      return Err(Unspecified);
    }
  };

  println!("Ciphertext: {}", HEXLOWER.encode(&cyphertext));

  let json_payload = json!( {
    "encryptedBlob":HEXLOWER.encode(&cyphertext),
    "authData": "encryptData",
    "iv": HEXLOWER.encode(&iv),
    "salt": HEXLOWER.encode(&salt),
  });

  let payload_text = match serde_json::to_string(&json_payload) {
    Ok(s) => s,
    Err(e) => panic!("Error converting to string: {}", e),
  };

  println!("Payload: {}", payload_text);

  Ok(payload_text)
}

fn login(password: &[u8]) {
  let f = get_encrypted_login_payload(password);
  match f {
    Ok(_) => println!("Login successful"),
    Err(_) => println!("Login failed"),
  }
}

pub fn get_lightring_state() {
  // TODO: Implement this function
  login("password");
  println!("get_lightring_state");
}

pub fn set_lightring_state(state: u8) {
  // TODO: Implement this function
  println!("set_lightring_state {}", state);
}
