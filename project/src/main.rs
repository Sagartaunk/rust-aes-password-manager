use ::app::account_build;
use app::app;
fn main(){
    account_build::create_account();
    app::run();
}