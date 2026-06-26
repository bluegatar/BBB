//! mp4decrypt — a Rust port of Bento4's mp4decrypt for progressive (non-fragmented)
//! CENC (AES-128-CTR) MP4 files, plus a `--download` mode that fetches and
//! decrypts a protected video described by a video-model JSON file.

mod download;
mod model;
mod mp4;
mod spade;

use std::collections::HashMap;
use std::process::ExitCode;

const DEFAULT_OUTPUT: &str = "decrypted.mp4";
const DOWNLOAD_THREADS: usize = 3;

/// Keys indexed by KID and by 1-based track id, respectively.
type KeyMaps = (HashMap<[u8; 16], [u8; 16]>, HashMap<u32, [u8; 16]>);

fn usage() -> &'static str {
    "\
mp4decrypt — decrypt CENC (AES-128-CTR) MP4 files

USAGE:
  mp4decrypt [--key <id>:<hex> ...] <input.mp4> <output.mp4>
  mp4decrypt --download <video_model.json> [--out <output.mp4>]

OPTIONS:
  --key <id>:<hex>   Decryption key. <id> is a 1-based track id (decimal) or a
                     32-hex-char KID; <hex> is the 32-hex-char (128-bit) key.
                     May be repeated. Required unless --download is used.
  --download <json>  Read a video-model JSON file, pick the last (highest
                     quality) video, download its main_url with 3 threads,
                     derive the key from spade_a, and decrypt it. No --key needed.
  --out <file>       Output file name (only with --download). The temporary
                     encrypted download is removed afterwards. Defaults to
                     'decrypted.mp4'.
  -h, --help         Show this help.
"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{}", usage());
        return Ok(());
    }

    let mut keys: Vec<(String, String)> = Vec::new();
    let mut download_json: Option<String> = None;
    let mut out: Option<String> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--key" => {
                let v = args.get(i + 1).ok_or("--key requires <id>:<hex>")?;
                let (id, k) = v.split_once(':').ok_or("--key value must be <id>:<hex>")?;
                keys.push((id.to_string(), k.to_string()));
                i += 2;
            }
            "--download" => {
                let v = args.get(i + 1).ok_or("--download requires a json path")?;
                download_json = Some(v.clone());
                i += 2;
            }
            "--out" => {
                let v = args.get(i + 1).ok_or("--out requires a filename")?;
                out = Some(v.clone());
                i += 2;
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown option: {other}"));
            }
            _ => {
                positional.push(a.clone());
                i += 1;
            }
        }
    }

    if let Some(json_path) = download_json {
        if !keys.is_empty() {
            return Err("--key cannot be combined with --download".into());
        }
        if !positional.is_empty() {
            return Err("--download takes no positional <input>/<output> args".into());
        }
        run_download(&json_path, out.as_deref())
    } else {
        if out.is_some() {
            return Err("--out is only valid together with --download".into());
        }
        if keys.is_empty() {
            return Err("at least one --key is required (or use --download)".into());
        }
        if positional.len() != 2 {
            return Err("expected <input.mp4> <output.mp4>".into());
        }
        run_decrypt_file(&keys, &positional[0], &positional[1])
    }
}

/// Build key maps from `<id>:<hex>` pairs. An id is either a 32-hex-char KID or
/// a decimal track id.
fn build_keys(keys: &[(String, String)]) -> Result<KeyMaps, String> {
    let mut by_kid = HashMap::new();
    let mut by_track = HashMap::new();
    for (id, k) in keys {
        let key = parse_hex16(k).ok_or_else(|| format!("invalid 128-bit key: {k}"))?;
        if let Some(kid) = parse_hex16(id) {
            by_kid.insert(kid, key);
        } else if let Ok(track) = id.parse::<u32>() {
            by_track.insert(track, key);
        } else {
            return Err(format!(
                "invalid key id (expected track id or 32-hex KID): {id}"
            ));
        }
    }
    Ok((by_kid, by_track))
}

fn run_decrypt_file(keys: &[(String, String)], input: &str, output: &str) -> Result<(), String> {
    let (by_kid, by_track) = build_keys(keys)?;
    let buf = std::fs::read(input).map_err(|e| format!("reading {input}: {e}"))?;
    let mut mp4 = mp4::Mp4::parse(&buf)?;
    let n = mp4.decrypt(&by_kid, &by_track)?;
    if n == 0 {
        return Err("no tracks were decrypted (missing key or unprotected input)".into());
    }
    let out_buf = mp4.serialize();
    std::fs::write(output, &out_buf).map_err(|e| format!("writing {output}: {e}"))?;
    println!("decrypted {n} track(s) -> {output}");
    Ok(())
}

fn run_download(json_path: &str, out: Option<&str>) -> Result<(), String> {
    let text =
        std::fs::read_to_string(json_path).map_err(|e| format!("reading {json_path}: {e}"))?;
    let target = model::parse_video_model(&text)?;

    let kid = parse_hex16(&target.kid_hex)
        .ok_or_else(|| format!("invalid kid in JSON: {}", target.kid_hex))?;
    let key_hex = spade::spade_a_to_key_hex(&target.spade_a, 0)?;
    let key =
        parse_hex16(&key_hex).ok_or_else(|| format!("spade_a produced invalid key: {key_hex}"))?;

    println!("target video: {}", target.gear_des_key);
    println!("kid : {}", target.kid_hex);
    println!("key : {key_hex}");
    println!(
        "downloading {} with {DOWNLOAD_THREADS} threads...",
        target.main_url
    );

    let encrypted = download::download(&target.main_url, DOWNLOAD_THREADS)?;
    println!("downloaded {} bytes", encrypted.len());

    // Persist the encrypted download to a temp file (deleted after decryption).
    let tmp = format!("encrypted_{}.mp4", std::process::id());
    std::fs::write(&tmp, &encrypted).map_err(|e| format!("writing temp file {tmp}: {e}"))?;

    let output = out.unwrap_or(DEFAULT_OUTPUT);
    let result = (|| -> Result<(), String> {
        let mut mp4 = mp4::Mp4::parse(&encrypted)?;
        let mut by_kid = HashMap::new();
        by_kid.insert(kid, key);
        let n = mp4.decrypt(&by_kid, &HashMap::new())?;
        if n == 0 {
            return Err("no tracks were decrypted".into());
        }
        let out_buf = mp4.serialize();
        std::fs::write(output, &out_buf).map_err(|e| format!("writing {output}: {e}"))?;
        println!("decrypted {n} track(s) -> {output}");
        Ok(())
    })();

    // Always remove the temp encrypted file.
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Parse exactly 32 hex chars into 16 bytes.
fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex16_roundtrip() {
        let k = parse_hex16("6a316238f8818b04b952f1780002ebeb").unwrap();
        assert_eq!(k[0], 0x6a);
        assert_eq!(k[15], 0xeb);
        assert!(parse_hex16("zz").is_none());
        assert!(parse_hex16("6a31").is_none());
    }
}
