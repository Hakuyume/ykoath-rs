use chrono::offset::Utc;
use clap::Parser;
use ykoath_protocol::{calculate_all, YubiKey};

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    Code {
        #[clap(long)]
        single: bool,
        query: Option<String>,
    },
    List,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    let mut buf = Vec::new();
    let yubikey = YubiKey::connect(&mut buf)?;
    yubikey.select(&mut buf)?;

    match opts.command {
        Command::Code { single, query } => {
            fn challenge() -> [u8; 8] {
                // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L57
                // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L225-L226
                (Utc::now().timestamp() / 30).to_be_bytes()
            }

            // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L391-L393
            let mut responses = yubikey.calculate_all(true, &challenge(), &mut buf)?;
            if let Some(query) = query {
                responses.retain(|response| {
                    response
                        .name
                        .windows(query.len())
                        .any(|window| window == query.as_bytes())
                });
            }

            if let [calculate_all::Response { name, inner, .. }] = &responses[..] {
                let name = name.to_vec();
                let code = match *inner {
                    calculate_all::Inner::Response(response) => response.code(),
                    calculate_all::Inner::Hotp => todo!(),
                    calculate_all::Inner::Touch => {
                        eprintln!("Touch YubiKey ...");
                        let response = yubikey.calculate(true, &name, &challenge(), &mut buf)?;
                        response.code()
                    }
                };
                if single {
                    println!("{code}");
                } else {
                    println!("{}\t{code}", name.escape_ascii());
                };
            } else {
                anyhow::ensure!(
                    !single,
                    "Multiple matches, please make the query more specific.",
                );
                for response in responses {
                    let code = match response.inner {
                        calculate_all::Inner::Response(response) => response.code(),
                        calculate_all::Inner::Hotp => "-".to_string(),
                        calculate_all::Inner::Touch => "-".to_string(),
                    };
                    println!("{}\t{}", response.name.escape_ascii(), code);
                }
            }
        }
        Command::List => {
            for response in yubikey.list(&mut buf)? {
                println!("{}", response.name.escape_ascii());
            }
        }
    }

    Ok(())
}
