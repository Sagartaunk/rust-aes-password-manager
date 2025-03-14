use std::{io::Read ,fs::{self , File}};
use argon2::Argon2 ;
use rand::random;
use crate::{cli  , Aaccount};
use aes_gcm::{
    Aes256Gcm,
    Key,
    Nonce,
    aead::{Aead, KeyInit}
};
use hex;
use serde_json;


pub fn key_generator(password : String , salt : Vec<u8>) -> Key<Aes256Gcm> { // Generates keys
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    let _ = argon2.hash_password_into(&password.as_bytes() , &salt , &mut key);  
    let key = Key::<Aes256Gcm>::from_slice(&key).clone();
    key
}
fn load_from_file() -> std::io::Result<Vec<Aaccount>> { // Loads the accounts from the file
    let mut file = match File::open("passwords.json") {
        Ok(file) => file,
        Err(_) => return Ok(Vec::new()), // Return an empty vector if the file does not exist
    };
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    if data.trim().is_empty() {
        return Ok(Vec::new()); // Return an empty vector if the file is empty
    }
    let accounts: Vec<Aaccount> = serde_json::from_str(&data).expect("Failed to deserialize");
    Ok(accounts)
}
fn load_to_file(accounts : Vec<Aaccount>){ // Loads the accounts to the file
    let json = serde_json::to_string_pretty(&accounts).expect("Failed to serialize");
    fs::write("passwords.json", json).expect("Failed to write to file");
}

pub fn run(){// Main function which runs the program
    let choice = cli::menu();
    let choice = choice.trim();
    match choice{
        "1" => {add_password();},
        "2" => {password_view();},
        "3" => {delete_password();},
        "4" => {println!("Exiting...");},
        _ => {panic!("Invalid choice crashing the program");}
    };
} 

pub fn password_test() -> String { // Tests the password
    let password = cli::password_input();
    let key_txt = fs::read_to_string("key.txt").expect("Failed to read key file");
    let key_txt = key_txt.split(":").collect::<Vec<&str>>();
    let test = hex::decode(key_txt[0]).expect("Failed to decode");
    let salt = hex::decode(key_txt[1]).expect("Failed to decode");
    let nonce = hex::decode(key_txt[2]).expect("Failed to decode");
    let cipher = Aes256Gcm::new(&key_generator(password.clone() , salt));
    if cipher.decrypt(Nonce::from_slice(&nonce) , test.as_ref()).is_err(){
        println!("Wrong password");
        password_test();
    }else{
        println!("Password verified");
    }
    password
}

pub fn add_password(){ // Adds password to the file
    let password = password_test();
    let account = cli::account_input();
    let file = fs::read_to_string("key.txt").expect("Failed to read file");
    let file = file.split(":").collect::<Vec<&str>>();
    let nonce_bytes : [u8; 12] = random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(&key_generator(password , hex::decode(file[1]).expect("Failed to decode")));
    let encryptedacc = cipher.encrypt(&nonce , account.0.as_bytes()).expect("Failed to encrypt");
    let encryptedpass = cipher.encrypt(&nonce , account.1.as_bytes()).expect("Failed to encrypt");
    let aacount = Aaccount{
        account : hex::encode(encryptedacc),
        password : hex::encode(encryptedpass),
        nonce : hex::encode(nonce_bytes),
    };
    let mut accounts = load_from_file().unwrap_or_else(|_| Vec::new());
    // Push the new account to the vector
    accounts.push(aacount);
    // Save the updated accounts back to the file
    load_to_file(accounts);
}
pub fn password_view() {
    let password = password_test();
    let keyfile = fs::read_to_string("key.txt").expect("Failed to read key file");
    let keyfile = keyfile.split(":").collect::<Vec<&str>>();
    let salt = hex::decode(keyfile[1]).expect("Failed to decode salt");
    let key = key_generator(password , salt);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let accounts = load_from_file().expect("Failed to load accounts");
    for account in accounts{
        let account_name = hex::decode(&account.account).expect("Failed to decode account");
        let password = hex::decode(&account.password).expect("Failed to decode password");
        let nonce_bytes = hex::decode(&account.nonce).expect("Failed to decode nonce");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new(&key);
        let a_name = cipher.decrypt(&nonce , account_name.as_ref()).expect("Failed to decrypt account name");
        let a_password = cipher.decrypt(&nonce , password.as_ref()).expect("Failed to decrypt password");
        println!("Account : {} , Password : {}",String::from_utf8(a_name).expect("Failed to convert to string") , String::from_utf8(a_password).expect("Failed to convert to string"));


    }
}

pub fn delete_password() {
    let pass = password_test();
    println!("Showing passwords");
    password_view();
    let name = cli::account_name_input();
    let mut file = std::fs::File::open("passwords.json").expect("Failed to open passwords.json");
    let mut data = String::new();
    file.read_to_string(&mut data).expect("Failed to read passwords.json");
    let mut entries: Vec<Aaccount> = serde_json::from_str(&data).expect("Failed to deserialize passwords.json");
    let keytxt = fs::read_to_string("key.txt").expect("Failed to read key file");
    let keytxt = keytxt.split(":").collect::<Vec<&str>>();
    let salt = hex::decode(keytxt[1]).expect("Failed to decode salt");
    let salt = salt.to_vec();
    let key = key_generator(pass, salt);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let initial_len = entries.len();
    entries.retain(|entry| {
        let nonce_bytes = hex::decode(&entry.nonce).expect("Invalid nonce format");
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Attempt to decrypt the account name
        let decrypted_account = cipher.decrypt(nonce, hex::decode(&entry.account).unwrap().as_ref());

        // If decryption works and matches the target, remove it
        match decrypted_account {
            Ok(account_bytes) => {
                let account = String::from_utf8(account_bytes).expect("Invalid UTF-8");
                account != name // Keep only if account != name
            }
            Err(_) => true, // If decryption fails, keep the entry
        }
    });

    if entries.len() == initial_len {
        println!("Account '{}' not found.", name);
    } else {
        // Save the updated list back to the file
        let json = serde_json::to_string_pretty(&entries).expect("Failed to serialize");
        std::fs::write("passwords.json", json).expect("Failed to write passwords.json");
        println!("Account '{}' deleted.", name);
    }
}