pub fn split_to_two(value: &str, pat: &str) -> Option<[String; 2]> {
    let arr: Vec<&str> = value.split(pat).collect();
    if arr.len() < 2 {
        return None;
    }
    let value = arr[1..].join(pat).trim().to_string();

    Some([arr[0].to_string(), value])
}
