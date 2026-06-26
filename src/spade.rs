//! Port of `spade_a_to_cenc_key.py`.
//!
//! Converts a base64 `spade_a` token into the 32-hex-char CENC (AES-CTR)
//! content key. This is NOT standard crypto: it is a custom XOR + index
//! popcount byte transform reverse-engineered from libttmplayer.so. The logic
//! mirrors the reference Python implementation byte-for-byte.

use base64::Engine;

/// Convert a `spade_a` base64 token to the content-key hex string.
///
/// `flag` selects the additive-term sign, matching the Python `flag` argument
/// (default `0`).
pub fn spade_a_to_key_hex(spade_a_b64: &str, flag: u32) -> Result<String, String> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(spade_a_b64.trim())
        .map_err(|e| format!("bad spade_a base64: {e}"))?;
    let l = data.len();
    if l < 3 {
        return Err("bad spade_a (too short)".to_string());
    }

    // 1) header: n and output length come from the first 3 bytes
    let xb = (data[0] ^ data[1] ^ data[2]) as i32; // "magic" xor byte
    let n = xb - 0x30;
    if n < 1 {
        return Err("bad spade_a (n<1)".to_string());
    }
    let n = n as usize;
    let outlen = l as i32 - xb + 0x2f;
    if outlen < 1 {
        return Err("bad spade_a (outlen<1)".to_string());
    }
    let outlen = outlen as usize;

    // 2) trailing n bytes XOR'd -> tag (app_v2/web_v2 variants are unsupported)
    if l < n + 2 {
        return Err("bad spade_a (short tail)".to_string());
    }
    let xork = data[l - n - 1] ^ data[l - n - 2];
    let tag: Vec<u8> = (0..n).map(|i| data[l - n + i] ^ xork).collect();
    let app = b"app_v2";
    let web = b"web_v2";
    if (n <= app.len() && tag[..n] == app[..n]) || (n <= web.len() && tag[..n] == web[..n]) {
        return Err("app_v2/web_v2 variant not handled".to_string());
    }

    // 3) working buffer = data[1 : 1+outlen]
    if 1 + outlen > l {
        return Err("bad spade_a (outlen overflows data)".to_string());
    }
    let mut buf = data[1..1 + outlen].to_vec();

    // 4) custom per-byte transform: running pair of carries (0x55/0xfa) plus an
    //    index-popcount based additive term.
    let mut w11: u8 = 0x55;
    let mut w12: u8 = 0xfa;
    // `i` is used as the popcount input, not just an index, so iterate by index.
    #[allow(clippy::needless_range_loop)]
    for i in 0..outlen {
        let b = buf[i];
        let pc = (i as u32).count_ones() as i32;
        let carry = if i % 2 == 0 {
            let c = w12;
            w12 = b;
            c
        } else {
            let c = w11;
            w11 = b;
            c
        };
        let t = (carry ^ b) as i32;
        let delta = if flag == 0 { -0x15 - pc } else { pc + 0x15 };
        buf[i] = (delta + t) as u8; // implicit & 0xff via u8 truncation
    }

    // 5) split: buf[0] is a hex digit = hv; key = buf[1 : outlen-hv]
    let c = buf[0];
    let hv: i32 = if (0x30..=0x39).contains(&c) {
        c as i32 - 0x30
    } else if (0x61..=0x7a).contains(&c) {
        c as i32 - 0x57
    } else {
        0xff
    };
    if outlen as i32 - hv < 2 {
        return Err("bad split".to_string());
    }
    let end = outlen - hv as usize;
    let key_bytes = &buf[1..end];
    String::from_utf8(key_bytes.to_vec()).map_err(|e| format!("non-ascii key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // Verified anchor pairs from the reference Python script.
        assert_eq!(
            spade_a_to_key_hex("nbwTxVmyIcpcshvIU7Ev/WK2Kv5Qghn8SLIF/XqDBv9Xhx+pqQ==", 0).unwrap(),
            "0c3aaaeb0c0bd44511be1f8757ffcc7b"
        );
        assert_eq!(
            spade_a_to_key_hex("obwv9H+/N8NJjwfDTrg19Eq4N/RNvh32V40ewFOPHt5lpS25uQ==", 0).unwrap(),
            "d2951ef6751dc4f6f5b3801d154748ae"
        );
        // The video_model.json sample. (The Python script's inline expectation
        // for this case is a copy/paste typo; this is the algorithm's true
        // output, matching `spade_a_to_cenc_key.py` when actually executed.)
        assert_eq!(
            spade_a_to_key_hex("o7wtwFC5HvFRih7CYLkbxGS+HcdRvi/EY4wtw2aONsNltC2oqA==", 0).unwrap(),
            "bffc717e81fdcefdbb4bfb316725749a"
        );
    }

    #[test]
    fn key_is_32_hex_chars() {
        let k =
            spade_a_to_key_hex("o7wtwFC5HvFRih7CYLkbxGS+HcdRvi/EY4wtw2aONsNltC2oqA==", 0).unwrap();
        assert_eq!(k.len(), 32);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
