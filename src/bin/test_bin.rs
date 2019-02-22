use std::error::Error;
use hpfeeds::Hpfeeds;

fn main() -> Result<(), Box<Error>> {
    let hpf = Hpfeeds::new("host.com", 10000, "hpname", "elongated_muskrat")?;
    hpf.publish_to("chan1", b"hp hit")?;
    Ok(())
}
