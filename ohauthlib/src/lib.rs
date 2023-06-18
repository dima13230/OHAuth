use rand::Rng;
use std::char::MAX;
use std::collections::btree_map::Range;
use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Result;

use serialport as sp;
use sp::*;
use std::ffi::OsStr;
use std::io::prelude::*;
use udev::{Device, Enumerator};

use sha2::Sha256;

use aes::cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

#[derive(Serialize, Deserialize)]
struct AuthorizedBoards {
    boards: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct BoardResponse {
    hash: String,
    challenge: String
}

pub enum AuthResult {
    Success,
    Failure(String),
}

const BOARDS_JSON_FILENAME: &str = "regbs";

const USB_PRODUCT_NAME: &str = "OHAuth_Key";
const AES_KEY: &str = "OHAuthDefaultAES";
const XOR_KEY: &str = "OHAuthDefaultXOR";
const JSON_KEY: &str = "OHAuthDefaultJSONKey";
const MAX_READ_ATTEMPTS: u8 = 5;

pub fn attempt_auth() -> AuthResult {
    let boards_json_path = Path::new(BOARDS_JSON_FILENAME);
    let mut auth_boards: AuthorizedBoards;

    if boards_json_path.exists() {
        let mut file = match File::open(&boards_json_path) {
            Err(why) => {
                return AuthResult::Failure(
                    "Registered boards file exists but opening it wasn't successful.".to_string(),
                )
            }
            Ok(file) => file,
        };

        let mut boards_raw: Vec<u8> = vec![];
        match file.read_to_end(&mut boards_raw) {
            Err(why) => {
                return AuthResult::Failure("Couldn't read registered boards file.".to_string())
            }
            Ok(_) => println!("{} exists and is readable.", BOARDS_JSON_FILENAME),
        }
        let key_bytes = JSON_KEY.as_bytes();
        let key = GenericArray::clone_from_slice(key_bytes);

        let cipher = Aes256::new(&key);

        let mut boards_raw_generic = GenericArray::clone_from_slice(boards_raw.as_slice());
        cipher.decrypt_block(&mut boards_raw_generic);

        auth_boards = serde_json::from_slice(&boards_raw_generic.as_slice()).unwrap();
    } else {
        //return AuthResult::Failure(
        //    "Registered boards file doesn't exist. Register any board first.".to_string(),
        //);
    }

    // prepare AES256 cipher
    let key_bytes = AES_KEY.as_bytes();
    let key = GenericArray::clone_from_slice(key_bytes);
    let cipher = Aes256::new(&key);

    let mut enumerator = Enumerator::new().expect("Failed to create udev enumerator");
    enumerator
        .match_subsystem("tty")
        .expect("Failed to set subsystem filter");

    enumerator
        .match_property("ID_MODEL", USB_PRODUCT_NAME)
        .expect("Failed to set ID_MODEL filter");

    'outer: for device in enumerator.scan_devices().unwrap() {
        println!("{}", device.devnode().unwrap().to_str().unwrap());
        let mut port = serialport::new(device.devnode().unwrap().to_str().unwrap(), 115200)
            .timeout(Duration::from_secs(15))
            .stop_bits(StopBits::One)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .open_native()
            .expect(format!("Failed to open port {}", device.devnode().unwrap().to_str().unwrap()).as_str());

        std::thread::sleep(std::time::Duration::from_secs(2));

        if (!exchange_challenge(&mut port, &cipher)) {
            return AuthResult::Failure("Challenge test not passed.".to_string())
        }

        //let mut attempt: u8 = 0;
        /*loop {
            let available_bytes: u32 = port.bytes_to_read().expect("Failed to read buff size");
            if available_bytes > 0 {
                break;
            }

            // Number of attempts exceeded. Try other port, if any
            if attempt == MAX_READ_ATTEMPTS {
                continue 'outer;
            }
            std::thread::sleep(std::time::Duration::from_millis(1000));
            println!("No data");
            attempt += 1;
        }*/

        let mut serial_buf = vec![0; 1000];
        port.read(&mut serial_buf).unwrap();

        let mut string = match String::from_utf8(serial_buf) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };
        string = string.trim_matches(char::from(0)).to_owned();
        println!("{}", string);
    }
    return AuthResult::Failure("No functional OHAuth keys are connected to this device.".to_string());
}

fn exchange_challenge(port: &mut TTYPort, cipher: &Aes256) -> Result<String> {
    let mut rng = rand::thread_rng();

    let mut challenge: [u8; 32] = [0; 32];
    for i in 0..32 {
        let char = char::from_u32(rng.gen_range(32..127)).unwrap();
        challenge[i] = char as u8;
    }
    
    transform_challenge(&mut challenge, XOR_KEY.as_bytes());
    match port.write(&challenge) {
        Ok(_) => (),
        Err(_) => return Err(_)
    }
    
    // Read response with hash and challenge value as AES256 encrypted JSON
    let mut serial_buf = [0u8; 1000];
    port.read(&mut serial_buf).unwrap();

    let mut response = GenericArray::clone_from_slice(&serial_buf);
    cipher.decrypt_block(&mut response);

    let response_json: BoardResponse = serde_json::from_slice(&response).unwrap();

    Ok(response_json.hash)
}

fn transform_challenge(challenge: &mut [u8], transform_key: &[u8]) {
    for (i, byte) in challenge.iter_mut().enumerate() {
        *byte ^= transform_key[i % transform_key.len()];
    }
}
