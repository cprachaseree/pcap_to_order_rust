use std::env;
use std::iter::Skip;
use std::path::Path;

fn help() {
    println!("Usage: parse-quote [REORDER OPTION] INPUT_PCAP_PATH
Options:
    -h, --help          Display this message
    -r, --reorder       Reorders output parsed pcap in quote accept time")
}

#[derive(Default)]
pub struct UserArgs {
    pub reorder: bool,
    pub in_path: String
}

impl UserArgs {
    pub fn new() -> Self {
        Default::default()
    }
}

pub fn parse_args(user_args: &mut UserArgs) {
    let mut args: Skip<env::Args> = env::args().skip(1);

    if args.len() < 1 || args.len() > 2 {
        help();
        panic!("Invalid arguments. Exiting program.");
    }
    
    while let Some(arg) = args.next() {
        match &arg[..] {
            "-h" | "--help" => help(),
            "-r" | "--reorder" => {
                user_args.reorder = true;
            }, 
            _ => {
                user_args.in_path = arg.to_string();
            }
        }
    }

    // check if input pcap file exists
    if !Path::new(&user_args.in_path).is_file() {
        panic!("Invalid file '{}'. Exiting program.", &user_args.in_path);
    }
}