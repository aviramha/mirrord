mod lib;
// use lib::is_sip;


fn main() {
    // let path = std::env::args().last().unwrap();
    // println!("{path:?} is sip: {:?}", is_sip(&path));
    lib::patch_binary("/usr/bin/env", "/tmp/env").unwrap();
    println!("patched");
}