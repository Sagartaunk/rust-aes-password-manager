use serde::{Serialize, Deserialize};
pub mod app;
pub mod account_build;
pub mod cli;
#[derive(Serialize, Deserialize)]
pub struct Aaccount{
    account : String,
    password : String,
    nonce : String
}
