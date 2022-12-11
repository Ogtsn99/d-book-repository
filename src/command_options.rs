use libp2p::Multiaddr;
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "libp2p file sharing example")]
pub struct Opt {
    /// Fixed value to generate deterministic peer ID.
    #[clap(long)]
    pub secret_key_seed: Option<u8>,

    #[clap(long)]
    pub group: Option<u64>,

    #[clap(long)]
    pub peer: Option<Multiaddr>,

    #[clap(long)]
    pub listen_address: Option<Multiaddr>,

    #[clap(long)]
    pub rpc_url: Option<String>,

    #[clap(subcommand)]
    pub argument: CliArgument,
}

#[derive(Debug, Parser)]
pub enum CliArgument {
    Provide {},
    Get {
        #[clap(long)]
        name: String,
    },
    Upload {
        #[clap(long)]
        name: String,
    },
}