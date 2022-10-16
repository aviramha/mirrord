mod lib;
use lib::is_sip;


fn main() {
    let path = std::env::args().last().unwrap();
    println!("{path:?} is sip: {:?}", is_sip(&path));
}