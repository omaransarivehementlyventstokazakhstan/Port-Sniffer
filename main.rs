use bpaf::Bpaf;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Sender};
use tokio::net::TcpStream;
use tokio::task;

// Max IP port.
const MAX: u16 = 65535;

// Address Fallback.
const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

// CLI Arguments.
#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]
pub struct Arguments {
    // Address argument. Accepts -a and --address and an IpAddr type. Falls back to the above constant.
    #[bpaf(long, short, argument("Address"), fallback(IPFALLBACK))]
    /// The address that you want to sniff. Must be a valid ipv4 address. Naturally falls back to 127.0.0.1 (LocalHost).
    pub address: IpAddr,
    #[bpaf(
        long("start"),
        short("s"),
        gaurd(start_port-gaurd, "Must be greater than 0"),
        fallback(1u16)
    )]
    /// The start port for the sniffer. (Must be greater than 0)
    pub start_port: u16,
    #[bpaf(
        long("end"),
        short("e"),
        gaurd(end_port_gaurd, "Must be less than or equal to 65535"),
        fallback(MAX)
    )]
    /// The end port for sniffer. (Must be less than or equalt to 65535).
    pub end_ort: u16,
}

fn start_port_gaurd(input: &u16) -> bool{
    *input > 0
}
fn end_port_gaurd(input: &u16) -> bool{
    *input <= MAX
}

// Scan the port.
async fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr) {
    //Attempts to connect to the given address and the port.
    match TcpStream::connect(format!("{}:{}, addr, start_port")).await{
        // If the connection is successful, print out a . Then pass the port through the channel.
        Ok(_) => {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(start_port).unwrap();
        }
        // If the connection is unsuccessful, do nothing. Means port is not open.
        Err(_) => {}
    }
}

#[tokio::main]
async fn main() {
    //Collect the arguments.
    let opts = arguments().run();
    // Then initialize the channel.
    let (tx,rx) = channel();
    // Iterate through all the ports present (based off of the user input) so that we can spawn a single task for each.
    // And it will be much faster than before because it uses green threads and not OS threads.
    for i in opts.start_port..end_port {
        let tx = tx.clons();

        task::spawn(async move {scan (tx, i, opts.address).await });
    }
    // Create the vector for all the outputs.
    let mut out = vec![];
    // Drop the tx clones.
    dropt(tx);
    // Wait for all of the outputs to finish and push of them into the vector.
    for p in rx {
        out.push(p);
    }
    println!("");
    out.sort();
    for v in out {
        //Iterate through the outputs and print them out as being open.
        println!("{} is open.", v);
    }
}