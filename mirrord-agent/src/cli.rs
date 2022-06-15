use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Container id to get traffic from
    #[clap(short, long, value_parser)]
    pub container_id: Option<String>,

    /// Container runtime to use
    #[clap(short = 'r', long, value_parser)]
    pub container_runtime: Option<String>,

    /// Port to use for communication
    #[clap(short = 'l', long, default_value_t = 61337, value_parser)]
    pub communicate_port: u16,

    /// Communication timeout in seconds
    #[clap(short = 't', long, default_value_t = 30, value_parser)]
    pub communication_timeout: u16,

    /// Interface to use
    #[clap(short = 'i', long, default_value = "eth0", value_parser)]
    pub interface: String,
}

pub fn parse_args() -> Args {
    Args::parse()
}
