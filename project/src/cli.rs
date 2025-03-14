use std::io;
use rpassword::read_password;

pub fn password_input() -> String {
    println!("Enter password : ");
    let password = read_password().expect("Failed to read password");
    password.trim().to_string()
}
pub fn menu() -> String{
    println!("1. Add Password");
    println!("2. View Passwords");
    println!("3. Delete Password");
    println!("4. Exit");
    println!("Enter your choice : ");
    let mut choice = String::new();
    io::stdin().read_line(&mut choice).expect("Failed to read line");
    choice
}
pub fn account_input() -> (String , String){
    println!("Enter account name : ");
    let mut account = String::new();
    io::stdin().read_line(&mut account).expect("Failed to read line");
    println!("Enter password : ");
    let password = read_password().expect("Failed to read password");
    (account.trim().to_string() , password.trim().to_string())
}                       
pub fn account_name_input() -> String{
    println!("Enter account name : ");
    let mut account = String::new();
    io::stdin().read_line(&mut account).expect("Failed to read line");
    account.trim().to_string()
}