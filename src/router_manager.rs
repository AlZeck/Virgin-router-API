use data_encoding::HEXLOWER;
use reqwest;
use reqwest::header;
use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::{pbkdf2, rand};
use serde::Deserialize;
use serde_json::json;

use regex::Regex;

use std::num::NonZeroU32;

use aes::Aes128;
use ccm::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use ccm::{
  consts::{U16, U8},
  Ccm,
};

pub type AesCcm128 = Ccm<Aes128, U16, U8>;

#[derive(Debug, Deserialize)]
struct LoginResponse {
  p_status: String,
  nonce: Option<String>,
}

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

/**
 * Returns the following headers.
 *
 * Host: "192.168.0.1",
 * Origin: "http://192.168.0.1",
 * Referer: "http://192.168.0.1/",
*/
fn get_default_headers() -> header::HeaderMap {
  let mut headers = header::HeaderMap::new();

  headers.insert("Host", header::HeaderValue::from_static("192.168.0.1"));
  headers.insert(
    "Origin",
    header::HeaderValue::from_static("http://192.168.0.1"),
  );
  headers.insert(
    "Referer",
    header::HeaderValue::from_static("http://192.168.0.1/"),
  );

  headers
}

async fn login(password: &str) -> Result<(String, String), reqwest::Error> {
  let f = match get_encrypted_login_payload(password) {
    Ok(f) => f,
    Err(_) => panic!("Error generating the payload blob"),
  };

  let params = [("configInfo", f)];
  let client = reqwest::Client::new();
  let res: reqwest::Response = client
    .post("http://192.168.0.1/php/ajaxSet_Password.php")
    .headers(get_default_headers())
    .form(&params)
    .send()
    .await?;

  // get the cookie
  let cookie = {
    match &res.headers().get("set-cookie") {
      Some(c) => String::from(c.to_str().unwrap().clone()),
      None => panic!("No cookie found"),
    }
  };
  println!("\n\nCookie: {}", &cookie);

  let body = match res.json::<LoginResponse>().await {
    Ok(b) => b,
    Err(_) => panic!("Error logging in"),
  };
  println!("{}", body.p_status);

  let nonce = match body.nonce {
    Some(n) => n,
    None => panic!("No nonce found"),
  };
  println!("{}", nonce);
  Ok((cookie, nonce))
}

pub async fn get_lightring_state(password: &str) -> Result<i32, reqwest::Error> {
  let login_headers = match login(password).await {
    Ok(v) => v,
    Err(_) => panic!("Error logging in"),
  };
  let client = reqwest::Client::new();
  let mut headers = get_default_headers();

  headers.insert(
    "Cookie",
    header::HeaderValue::from_str(&login_headers.0).unwrap(),
  );

  headers.insert(
    "CSRF_NONCE",
    header::HeaderValue::from_str(&login_headers.1).unwrap(),
  );

  let res: reqwest::Response = client
    .get("http://192.168.0.1/php/lightring_data.php")
    .headers(headers)
    .send()
    .await?;

  let body = res.text().await?;

  let re = Regex::new(r"js_lightring_value = ([0-9]*);").unwrap();

  let status = re
    .captures(&body)
    .unwrap()
    .get(1)
    .unwrap()
    .as_str()
    .parse::<i32>()
    .unwrap();

  println!("get_lightring_state: {}", status);
  Ok(status)
}

pub async fn set_lightring_state(password: &str, state: u8) -> Result<(), reqwest::Error> {
  let login_headers = match login(password).await {
    Ok(v) => v,
    Err(_) => panic!("Error logging in"),
  };

  let client = reqwest::Client::new();
  let mut headers = get_default_headers();

  headers.insert(
    "Cookie",
    header::HeaderValue::from_str(&login_headers.0).unwrap(),
  );

  headers.insert(
    "CSRF_NONCE",
    header::HeaderValue::from_str(&login_headers.1).unwrap(),
  );

  let params = [
    ("lightRing", format!("{{\"lightRing\": {} }}", state)),
    ("opType", String::from("WRITE")),
  ];

  client
    .post("http://192.168.0.1/php/ajaxSet_lightring_data.php")
    .headers(headers)
    .form(&params)
    .send()
    .await?;

  println!("set_lightring_state {}", state);
  Ok(())
}
