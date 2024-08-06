
pub fn hex_to_bin(hex: &str) -> Vec<u8>
{
    let hex_trimmed = hex.trim();
    let hex_no_space =  str::replace(hex_trimmed, " ", "").replace("\n","").replace("\r", "");
    println!("hex_no_space: {}", hex_no_space);
    hex::decode(hex_no_space).expect("Decoding failed")
}


pub fn parse_hex_string(hex_string: &str) -> Vec<u8> {
    hex_string
        .split_whitespace()
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect()
}