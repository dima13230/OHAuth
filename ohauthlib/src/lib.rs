use rand::Rng;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use serialport as sp;
use sp::*;
use udev::{Enumerator};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
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

pub enum OHAuthResult {
    Success,
    NotRegistered,
    Error(String),
}

const BOARDS_JSON_FILENAME: &str = "regbs";

const USB_PRODUCT_NAME: &str = "OHAuth_Key";
const AES_KEY: &str = "OHAuthDefaultAES";
const XOR_KEY: &str = "OHAuthDefaultXOR";
const JSON_KEY: &str = "OHAuthDefaultJSONKey";

pub fn register() -> OHAuthResult {
    let auth_boards_json_path = Path::new(BOARDS_JSON_FILENAME);
    let mut auth_boards_json_file: File;
    let mut auth_boards: AuthorizedBoards = AuthorizedBoards { boards: vec![] };

    let key_bytes_json = JSON_KEY.as_bytes();
    let key_len = key_bytes_json.len();
    let key_json = GenericArray::clone_from_slice(&key_bytes_json[0..key_len]);

    let cipher_json = Aes256::new(&key_json);
    if auth_boards_json_path.exists() {
        auth_boards_json_file = match File::open(auth_boards_json_path) {
            Err(why) => {
                return OHAuthResult::Error(
                    format!("Registered boards file exists but opening it wasn't successful. {}", why),
                )
            }
            Ok(file) => file,
        };

        let mut boards_raw: Vec<u8> = vec![];
        match auth_boards_json_file.read_to_end(&mut boards_raw) {
            Err(why) => {
                return OHAuthResult::Error(format!("Couldn't read registered boards file. {}", why))
            }
            Ok(_) => ()
        }

        let mut boards_raw_generic = GenericArray::clone_from_slice(boards_raw.as_slice());
        cipher_json.decrypt_block(&mut boards_raw_generic);

        auth_boards = serde_json::from_slice(&boards_raw_generic.as_slice()).unwrap();
    } else {
        auth_boards_json_file = match File::create(auth_boards_json_path) {
            Err(why) => {
                return OHAuthResult::Error(format!("Couldn't create registered boards file. {}", why))
            },
            Ok(file) => file
        };
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

    for device in enumerator.scan_devices().unwrap() {
        println!("{}", device.devnode().unwrap().to_str().unwrap());
        let mut port = serialport::new(device.devnode().unwrap().to_str().unwrap(), 115200)
            .timeout(Duration::from_secs(15))
            .stop_bits(StopBits::One)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .open_native()
            .expect(format!("Failed to open port {}", device.devnode().unwrap().to_str().unwrap()).as_str());

        // Arduino boards reset after Serial connection is established, so we have to have delay before we continue working with it
        std::thread::sleep(std::time::Duration::from_secs(2));

        let board_hash = match exchange_challenge(&mut port, &cipher) {
            Ok(string) => string,
            Err(why) => return OHAuthResult::Error(format!("Challenge test not passed. {}", why))
        };
        
        auth_boards.boards.push(board_hash);
        let auth_boards_json = match serde_json::to_string(&auth_boards) {
            Ok(string) => string,
            Err(e) => return OHAuthResult::Error(format!("Couldn't convert auth_boards to JSON. {}", e))
        };

        let mut auth_boards_json_bytes_encrypted = GenericArray::clone_from_slice(auth_boards_json.as_bytes());
        cipher_json.encrypt_block(&mut auth_boards_json_bytes_encrypted);

        match auth_boards_json_file.write_all(&auth_boards_json_bytes_encrypted.as_slice()) {
            Ok(_) => return OHAuthResult::Success,
            Err(why) => return OHAuthResult::Error(format!("Couldn't write to registered boards file! {}", why))
        };
    }
    OHAuthResult::Error("No functional OHAuth keys are connected to this device.".to_string())
}

pub fn authorize() -> OHAuthResult {
    let boards_json_path = Path::new(BOARDS_JSON_FILENAME);
    let mut auth_boards: AuthorizedBoards = AuthorizedBoards { boards: vec![] };

    if boards_json_path.exists() {
        let mut file = match File::open(&boards_json_path) {
            Err(why) => {
                return OHAuthResult::Error(
                    format!("Registered boards file exists but opening it wasn't successful. {}", why),
                )
            }
            Ok(file) => file,
        };

        let mut boards_raw: Vec<u8> = vec![];
        match file.read_to_end(&mut boards_raw) {
            Err(why) => {
                return OHAuthResult::Error(format!("Couldn't read registered boards file. {}", why))
            }
            Ok(_) => ()
        }
        let key_bytes = JSON_KEY.as_bytes();
        let key = GenericArray::clone_from_slice(key_bytes);

        let cipher = Aes256::new(&key);

        let mut boards_raw_generic = GenericArray::clone_from_slice(boards_raw.as_slice());
        cipher.decrypt_block(&mut boards_raw_generic);

        auth_boards = serde_json::from_slice(&boards_raw_generic.as_slice()).unwrap();
    } else {
        return OHAuthResult::NotRegistered;
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

    for device in enumerator.scan_devices().unwrap() {
        println!("{}", device.devnode().unwrap().to_str().unwrap());
        let mut port = serialport::new(device.devnode().unwrap().to_str().unwrap(), 115200)
            .timeout(Duration::from_secs(15))
            .stop_bits(StopBits::One)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .open_native()
            .expect(format!("Failed to open port {}", device.devnode().unwrap().to_str().unwrap()).as_str());

        // Arduino boards reset after Serial connection is established, so we have to have delay before continue working with it
        std::thread::sleep(std::time::Duration::from_secs(2));

        let board_hash = match exchange_challenge(&mut port, &cipher) {
            Ok(string) => string,
            Err(why) => return OHAuthResult::Error(format!("Challenge test not passed. {}", why))
        };
        
        for board in &auth_boards.boards {
            if board_hash.eq(board) {
                return OHAuthResult::Success
            }
        }

        return OHAuthResult::NotRegistered
    }
    return OHAuthResult::Error("No functional OHAuth keys are connected to this device.".to_string())
}

fn exchange_challenge(port: &mut TTYPort, cipher: &Aes256) -> serialport::Result<String> {
    let mut rng = rand::thread_rng();

    // Generate random challenge value that is string made of random printable characters
    let mut challenge: [u8; 32] = [0; 32];
    for i in 0..32 {
        let char = char::from_u32(rng.gen_range(32..127)).unwrap();
        challenge[i] = char as u8;
    }

    // Encrypt challenge
    let mut challenge_enc = GenericArray::clone_from_slice(&challenge);
    cipher.encrypt_block(&mut challenge_enc);
    
    match port.write(&challenge_enc) {
        Ok(_) => (),
        Err(e) => return Err(e.into())
    };
    
    // Read response with hash and challenge value as AES256 encrypted JSON
    let mut serial_buf = [0u8; 1024];
    port.read(&mut serial_buf).unwrap();

    let mut response = GenericArray::clone_from_slice(&serial_buf);
    cipher.decrypt_block(&mut response);

    let response_json: BoardResponse = serde_json::from_slice(&response.as_slice()).unwrap();

    // Now transform challenge and compare
    transform_challenge(&mut challenge, XOR_KEY.as_bytes());
    if response_json.challenge.as_bytes() != challenge {
        return Err(serialport::Error::new(ErrorKind::InvalidInput, "Challenge values do not match"))
    }

    Ok(response_json.hash)
}

fn transform_challenge(challenge: &mut [u8], transform_key: &[u8]) {
    for (i, byte) in challenge.iter_mut().enumerate() {
        *byte ^= transform_key[i % transform_key.len()];
    }
}
