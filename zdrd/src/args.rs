use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The match threshold
    #[arg(short)]
    pub r: f64,

    /// Path to the face detector DB
    #[arg(long)]
    pub ddb: String,

    ///Path to the prediction DB
    #[arg(long)]
    pub pdb: String,

    /// Path to the recognition DB
    #[arg(long)]
    pub rdb: String,

    /// Auth image directory
    #[arg(long)]
    pub auth_dir: String,

    /// The video device
    #[arg(long)]
    pub camera: String,
}
