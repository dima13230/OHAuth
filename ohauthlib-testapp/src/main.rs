use ohauthlib::OHAuthResult;

extern crate ohauthlib;

fn main() {
    loop {
        let result = ohauthlib::authorize();
        match result {
            ohauthlib::OHAuthResult::Success => {
                println!("Congrats! You successfully authentificated to gain access to nothing!");
            }
            ohauthlib::OHAuthResult::NotRegistered => {
                // TODO
                match ohauthlib::register() {
                    OHAuthResult::Success => {

                    },
                    OHAuthResult::NotRegistered => {

                    },
                    OHAuthResult::Error(e) => {

                    }
                }
            }
            ohauthlib::OHAuthResult::Error(why) => {
                println!("Couldn't authentificate! Error: {}", why);
            }
        }
    }
}
