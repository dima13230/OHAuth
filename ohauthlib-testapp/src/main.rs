extern crate ohauthlib;

fn main() {
    let result = ohauthlib::attempt_auth();
    match result {
        ohauthlib::AuthResult::Success => {
            println!("Congrats! You successfully authentificated to gain access to nothing!");
        },
        ohauthlib::AuthResult::Failure(why) => {
            println!("Couldn't authentificate! Error: {}", why);
        }
    }
}

