#[macro_use]
extern crate bitfield;

use getopts::Options;
use std::env;

mod dns;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();
    let program = args[0].clone();

    opts.optflag("h", "help", "print help");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => panic!("{}", e.to_string()),
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    dns::query_dns_server(&args[1]);
}
