use chrono::offset::Utc;
use clap::Parser;
use ykoath_protocol::{calculate_all, YubiKey};

#[derive(Parser)]
struct Opts {
    #[clap(long)]
    name: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    let mut buf = Vec::new();
    let yubikey = YubiKey::connect(&mut buf)?;
    yubikey.select(&mut buf)?;

    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L57
    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L225-L226
    let challenge = (Utc::now().timestamp() / 30).to_be_bytes();

    // https://github.com/Yubico/yubikey-manager/blob/4.0.9/yubikit/oath.py#L391-L393
    let response = yubikey
        .calculate_all(true, &challenge, &mut buf)?
        .into_iter()
        .find(|response| response.name == opts.name.as_bytes())
        .ok_or_else(|| anyhow::format_err!("no account: {}", opts.name))?;

    let response = match response.inner {
        calculate_all::Inner::Response(response) => response,
        calculate_all::Inner::Hotp => anyhow::bail!("HOTP is not supported"),
        calculate_all::Inner::Touch => {
            eprintln!("Touch YubiKey ...");
            yubikey.calculate(true, opts.name.as_bytes(), &challenge, &mut buf)?
        }
    };
    println!("{}", response.code());

    Ok(())
}
