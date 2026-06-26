//! Simple multi-threaded HTTP downloader using ranged GET requests.

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread;

/// Download `url` into a single `Vec<u8>` using `threads` parallel workers,
/// each fetching a contiguous byte range. Falls back to a single streamed GET
/// when the server does not advertise a content length or range support.
pub fn download(url: &str, threads: usize) -> Result<Vec<u8>, String> {
    let threads = threads.max(1);

    // HEAD to learn the size and whether ranges are supported.
    let head = ureq::head(url)
        .call()
        .map_err(|e| format!("HEAD request failed: {e}"))?;
    let total: Option<u64> = head
        .header("Content-Length")
        .and_then(|s| s.parse::<u64>().ok());
    let accept_ranges = head
        .header("Accept-Ranges")
        .map(|s| s.eq_ignore_ascii_case("bytes"))
        .unwrap_or(false);

    let total = match total {
        Some(t) if t > 0 && (accept_ranges || threads == 1) => t,
        _ => return download_single(url),
    };

    if threads == 1 {
        return download_single(url);
    }

    let chunk = total.div_ceil(threads as u64);
    let buf = Arc::new(Mutex::new(vec![0u8; total as usize]));
    let mut handles = Vec::new();

    for i in 0..threads as u64 {
        let start = i * chunk;
        if start >= total {
            break;
        }
        let end = ((i + 1) * chunk).min(total) - 1; // inclusive
        let url = url.to_string();
        let buf = Arc::clone(&buf);
        handles.push(thread::spawn(move || -> Result<(), String> {
            let range = format!("bytes={start}-{end}");
            let resp = ureq::get(&url)
                .set("Range", &range)
                .call()
                .map_err(|e| format!("range {range} failed: {e}"))?;
            let mut data = Vec::with_capacity((end - start + 1) as usize);
            resp.into_reader()
                .read_to_end(&mut data)
                .map_err(|e| format!("reading range {range}: {e}"))?;
            let mut guard = buf.lock().unwrap();
            let s = start as usize;
            if s + data.len() > guard.len() {
                return Err("range response larger than expected".into());
            }
            guard[s..s + data.len()].copy_from_slice(&data);
            Ok(())
        }));
    }

    for h in handles {
        h.join()
            .map_err(|_| "download thread panicked".to_string())??;
    }

    let data = Arc::try_unwrap(buf)
        .map_err(|_| "buffer still shared".to_string())?
        .into_inner()
        .map_err(|_| "buffer lock poisoned".to_string())?;
    Ok(data)
}

fn download_single(url: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("GET failed: {e}"))?;
    let mut data = Vec::new();
    resp.into_reader()
        .read_to_end(&mut data)
        .map_err(|e| format!("reading body: {e}"))?;
    Ok(data)
}
