//! Parsing of the video-model JSON used by `--download`.
//!
//! Structure: top-level object -> `data.video_model` (a JSON *string* that must
//! be parsed again) -> `video_list` (array). The last entry is the highest
//! quality (1080p) stream and carries `main_url` plus `encrypt_info`.

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct TargetVideo {
    pub main_url: String,
    pub kid_hex: String,
    pub spade_a: String,
    pub gear_des_key: String,
}

pub fn parse_video_model(text: &str) -> Result<TargetVideo, String> {
    let outer: Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;

    // data.video_model is itself a JSON-encoded string.
    let vm_str = outer
        .get("data")
        .and_then(|d| d.get("video_model"))
        .and_then(|v| v.as_str())
        .ok_or("missing data.video_model string")?;
    let inner: Value =
        serde_json::from_str(vm_str).map_err(|e| format!("invalid data.video_model JSON: {e}"))?;

    let list = inner
        .get("video_list")
        .and_then(|v| v.as_array())
        .ok_or("missing video_list array")?;
    let last = list.last().ok_or("video_list is empty")?;

    let main_url = last
        .get("main_url")
        .and_then(|v| v.as_str())
        .ok_or("last video has no main_url")?
        .to_string();

    let enc = last
        .get("encrypt_info")
        .ok_or("last video has no encrypt_info")?;
    let kid_hex = enc
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or("encrypt_info has no kid")?
        .to_string();
    let spade_a = enc
        .get("spade_a")
        .and_then(|v| v.as_str())
        .ok_or("encrypt_info has no spade_a")?
        .to_string();
    let gear_des_key = last
        .get("gear_des_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(TargetVideo {
        main_url,
        kid_hex,
        spade_a,
        gear_des_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_model() {
        let inner = serde_json::json!({
            "video_list": [
                {"main_url": "https://a/360", "gear_des_key": "4:360p",
                 "encrypt_info": {"kid": "aa", "spade_a": "x"}},
                {"main_url": "https://a/1080", "gear_des_key": "4:1080p",
                 "encrypt_info": {"kid": "6a316238f8818b04b952f1780002ebeb",
                                  "spade_a": "o7wtwFC5HvFRih7CYLkbxGS+HcdRvi/EY4wtw2aONsNltC2oqA=="}}
            ]
        });
        let outer = serde_json::json!({
            "data": {"video_model": serde_json::to_string(&inner).unwrap()}
        });
        let t = parse_video_model(&serde_json::to_string(&outer).unwrap()).unwrap();
        assert_eq!(t.main_url, "https://a/1080");
        assert_eq!(t.kid_hex, "6a316238f8818b04b952f1780002ebeb");
        assert_eq!(t.gear_des_key, "4:1080p");
    }
}
