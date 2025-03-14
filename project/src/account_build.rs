pub fn create_account(){
    use std::fs::{self ,File};
    use crate::{app , cli };
    use hex;
    use rand::random;
    use aes_gcm::{
        Aes256Gcm,

        Nonce,
        aead::{Aead, KeyInit}
    };
    let file = File::open("key.txt");
    match file {
        Ok(_file) => {},
        Err(_error) => {
            println!{"Please create a master password : "};
            let master_password = cli::password_input();
            let salt : [u8; 32] = random(); 
            let salt = salt.to_vec();
            let key = app::key_generator(master_password.clone() , salt.clone());
            let cipher = Aes256Gcm::new(&key);
            let n : [u8; 12] = random();
            let nonce = Nonce::from_slice(&n);
            let test = cipher.encrypt(nonce , "test".as_bytes().as_ref()).expect("Failed to encrypt");
            let _ = File::create("key.txt").expect("Failed to create key file");
            let encoded = format!(
                "{}:{}:{}",
                hex::encode(test),
                hex::encode(salt),
                hex::encode(nonce),
            );
            let _ = fs::write("key.txt" , encoded).expect("Failed to write to key file");
            println!("done");       
        }
    }
}