//! Minimal MP4 (ISO-BMFF) reader/writer with progressive CENC (AES-128-CTR)
//! decryption. This is a focused Rust port of the parts of Bento4 that
//! `mp4decrypt` exercises for non-fragmented ("progressive") CENC content:
//!
//!   * walk `moov/trak/.../stbl`,
//!   * read the `senc` per-sample IV / subsample table (Bento4's patched
//!     progressive path),
//!   * locate each sample in `mdat` via `stsz`/`stsc`/`stco`|`co64`,
//!   * AES-128-CTR decrypt the encrypted byte ranges,
//!   * rewrite the protected sample entry to its original format, drop
//!     `sinf`/`senc`/`saiz`/`saio`, and fix up chunk offsets.
//!
//! It intentionally does not implement fragmented-MP4 decryption.

use std::collections::HashMap;

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Extract the track id from a `tkhd` box body (version 0 or 1).
fn parse_track_id(data: &[u8]) -> Option<u32> {
    if data.len() < 4 {
        return None;
    }
    let version = data[0];
    let off = if version == 1 { 20 } else { 12 };
    if data.len() < off + 4 {
        return None;
    }
    Some(be32(&data[off..off + 4]))
}

/// Container box types and the number of bytes between the 8-byte box header
/// and the first child box. `None` means the box is treated as an opaque leaf.
fn container_fixed_header(typ: &[u8; 4]) -> Option<usize> {
    match typ {
        b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"dinf" | b"edts" | b"udta" | b"mvex"
        | b"moof" | b"traf" | b"mfra" | b"sinf" | b"schi" => Some(0),
        b"stsd" => Some(8), // fullbox(4) + entry_count(4)
        // Only the *encrypted* sample entries need to be descended into; every
        // other sample entry is kept as an opaque leaf and re-serialized
        // byte-for-byte.
        b"encv" => Some(78), // VisualSampleEntry fixed part
        b"enca" => Some(28), // AudioSampleEntry fixed part
        _ => None,
    }
}

#[derive(Debug)]
pub enum BoxKind {
    Container {
        fixed_header: Vec<u8>,
        children: Vec<Mp4Box>,
    },
    Leaf {
        data: Vec<u8>,
    },
}

#[derive(Debug)]
pub struct Mp4Box {
    pub typ: [u8; 4],
    pub kind: BoxKind,
}

impl Mp4Box {
    fn parse_list(buf: &[u8]) -> Result<Vec<Mp4Box>, String> {
        let mut boxes = Vec::new();
        let mut pos = 0usize;
        while pos + 8 <= buf.len() {
            let size32 = be32(&buf[pos..]) as u64;
            let mut typ = [0u8; 4];
            typ.copy_from_slice(&buf[pos + 4..pos + 8]);
            let (header_len, total) = if size32 == 1 {
                if pos + 16 > buf.len() {
                    return Err("truncated 64-bit box header".into());
                }
                (16usize, be64(&buf[pos + 8..]))
            } else if size32 == 0 {
                // extends to end of buffer
                (8usize, (buf.len() - pos) as u64)
            } else {
                (8usize, size32)
            };
            if total < header_len as u64 || pos + total as usize > buf.len() {
                return Err(format!(
                    "box {:?} has bad size {} at pos {}",
                    String::from_utf8_lossy(&typ),
                    total,
                    pos
                ));
            }
            let end = pos + total as usize;
            let body = &buf[pos + header_len..end];
            let kind = match container_fixed_header(&typ) {
                Some(fh) if body.len() >= fh => {
                    let fixed_header = body[..fh].to_vec();
                    let children = Mp4Box::parse_list(&body[fh..])?;
                    BoxKind::Container {
                        fixed_header,
                        children,
                    }
                }
                _ => BoxKind::Leaf {
                    data: body.to_vec(),
                },
            };
            boxes.push(Mp4Box { typ, kind });
            pos = end;
        }
        Ok(boxes)
    }

    fn body_len(&self) -> u64 {
        match &self.kind {
            BoxKind::Leaf { data } => data.len() as u64,
            BoxKind::Container {
                fixed_header,
                children,
            } => {
                fixed_header.len() as u64 + children.iter().map(|c| c.serialized_len()).sum::<u64>()
            }
        }
    }

    fn serialized_len(&self) -> u64 {
        let body = self.body_len();
        if body + 8 > u32::MAX as u64 {
            body + 16
        } else {
            body + 8
        }
    }

    fn write_into(&self, out: &mut Vec<u8>) {
        let body = self.body_len();
        if body + 8 > u32::MAX as u64 {
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(&self.typ);
            out.extend_from_slice(&(body + 16).to_be_bytes());
        } else {
            out.extend_from_slice(&((body + 8) as u32).to_be_bytes());
            out.extend_from_slice(&self.typ);
        }
        match &self.kind {
            BoxKind::Leaf { data } => out.extend_from_slice(data),
            BoxKind::Container {
                fixed_header,
                children,
            } => {
                out.extend_from_slice(fixed_header);
                for c in children {
                    c.write_into(out);
                }
            }
        }
    }

    fn child(&self, t: &[u8; 4]) -> Option<&Mp4Box> {
        if let BoxKind::Container { children, .. } = &self.kind {
            children.iter().find(|c| &c.typ == t)
        } else {
            None
        }
    }

    fn child_mut(&mut self, t: &[u8; 4]) -> Option<&mut Mp4Box> {
        if let BoxKind::Container { children, .. } = &mut self.kind {
            children.iter_mut().find(|c| &c.typ == t)
        } else {
            None
        }
    }

    fn leaf(&self) -> Option<&[u8]> {
        match &self.kind {
            BoxKind::Leaf { data } => Some(data),
            _ => None,
        }
    }
}

fn find_path<'a>(b: &'a Mp4Box, path: &[&[u8; 4]]) -> Option<&'a Mp4Box> {
    let mut cur = b;
    for seg in path {
        cur = cur.child(seg)?;
    }
    Some(cur)
}

/// Per-sample crypto info parsed from a `senc` atom.
struct SampleCrypt {
    iv: Vec<u8>,
    subsamples: Vec<(u16, u32)>, // (clear, encrypted)
}

const SENC_FLAG_OVERRIDE: u32 = 0x1;
const SENC_FLAG_SUBSAMPLES: u32 = 0x2;

/// Parse a `senc` leaf payload into the per-sample table. `default_iv_size`
/// comes from the `tenc` atom and is used unless `senc` overrides it.
fn parse_senc(data: &[u8], default_iv_size: usize) -> Result<Vec<SampleCrypt>, String> {
    if data.len() < 8 {
        return Err("senc too small".into());
    }
    let flags = be32(&data[0..4]) & 0x00ff_ffff;
    let mut p = 4usize;
    let mut iv_size = default_iv_size;
    if flags & SENC_FLAG_OVERRIDE != 0 {
        // algorithm_id(3) + per_sample_iv_size(1) + kid(16)
        if data.len() < p + 20 {
            return Err("senc override header truncated".into());
        }
        iv_size = data[p + 3] as usize;
        p += 20;
    }
    if data.len() < p + 4 {
        return Err("senc missing sample_count".into());
    }
    let sample_count = be32(&data[p..p + 4]) as usize;
    p += 4;

    let has_subsamples = flags & SENC_FLAG_SUBSAMPLES != 0;
    let mut out = Vec::with_capacity(sample_count);
    for _ in 0..sample_count {
        if data.len() < p + iv_size {
            return Err("senc IV truncated".into());
        }
        let iv = data[p..p + iv_size].to_vec();
        p += iv_size;
        let mut subsamples = Vec::new();
        if has_subsamples {
            if data.len() < p + 2 {
                return Err("senc subsample count truncated".into());
            }
            let n = be16(&data[p..p + 2]) as usize;
            p += 2;
            if data.len() < p + n * 6 {
                return Err("senc subsample entries truncated".into());
            }
            for _ in 0..n {
                let clear = be16(&data[p..p + 2]);
                let enc = be32(&data[p + 2..p + 6]);
                subsamples.push((clear, enc));
                p += 6;
            }
        }
        out.push(SampleCrypt { iv, subsamples });
    }
    Ok(out)
}

/// `tenc` parsed defaults.
struct Tenc {
    kid: [u8; 16],
    per_sample_iv_size: u8,
    crypt_byte_block: u8,
    skip_byte_block: u8,
}

fn parse_tenc(data: &[u8]) -> Result<Tenc, String> {
    // version(1) flags(3) reserved(1) {reserved|blocks}(1) is_protected(1)
    // per_sample_iv_size(1) kid(16) [constant_iv...]
    if data.len() < 24 {
        return Err("tenc too small".into());
    }
    let version = data[0];
    let blocks = data[5];
    let (crypt_byte_block, skip_byte_block) = if version == 0 {
        (0u8, 0u8)
    } else {
        ((blocks >> 4) & 0xF, blocks & 0xF)
    };
    let per_sample_iv_size = data[7];
    let mut kid = [0u8; 16];
    kid.copy_from_slice(&data[8..24]);
    Ok(Tenc {
        kid,
        per_sample_iv_size,
        crypt_byte_block,
        skip_byte_block,
    })
}

fn parse_stsz(data: &[u8]) -> Result<Vec<u32>, String> {
    if data.len() < 12 {
        return Err("stsz too small".into());
    }
    let sample_size = be32(&data[4..8]);
    let sample_count = be32(&data[8..12]) as usize;
    if sample_size != 0 {
        return Ok(vec![sample_size; sample_count]);
    }
    if data.len() < 12 + sample_count * 4 {
        return Err("stsz entries truncated".into());
    }
    let mut v = Vec::with_capacity(sample_count);
    for i in 0..sample_count {
        v.push(be32(&data[12 + i * 4..]));
    }
    Ok(v)
}

fn parse_stsc(data: &[u8]) -> Result<Vec<(u32, u32, u32)>, String> {
    if data.len() < 8 {
        return Err("stsc too small".into());
    }
    let count = be32(&data[4..8]) as usize;
    if data.len() < 8 + count * 12 {
        return Err("stsc entries truncated".into());
    }
    let mut v = Vec::with_capacity(count);
    for i in 0..count {
        let o = 8 + i * 12;
        v.push((be32(&data[o..]), be32(&data[o + 4..]), be32(&data[o + 8..])));
    }
    Ok(v)
}

fn parse_chunk_offsets(b: &Mp4Box) -> Result<Vec<u64>, String> {
    let data = b.leaf().ok_or("chunk offset box is not a leaf")?;
    if data.len() < 8 {
        return Err("stco/co64 too small".into());
    }
    let count = be32(&data[4..8]) as usize;
    let mut v = Vec::with_capacity(count);
    if &b.typ == b"co64" {
        if data.len() < 8 + count * 8 {
            return Err("co64 entries truncated".into());
        }
        for i in 0..count {
            v.push(be64(&data[8 + i * 8..]));
        }
    } else {
        if data.len() < 8 + count * 4 {
            return Err("stco entries truncated".into());
        }
        for i in 0..count {
            v.push(be32(&data[8 + i * 4..]) as u64);
        }
    }
    Ok(v)
}

/// Compute the absolute file offset of every sample, in decode order, from the
/// sample table boxes.
fn sample_offsets(sizes: &[u32], stsc: &[(u32, u32, u32)], chunk_offsets: &[u64]) -> Vec<u64> {
    let mut offsets = Vec::with_capacity(sizes.len());
    let mut si = 0usize;
    for (ci, &chunk_off) in chunk_offsets.iter().enumerate() {
        let chunk_no = (ci + 1) as u32;
        // samples-per-chunk = the entry with the greatest first_chunk <= chunk_no
        let spc = stsc
            .iter()
            .rev()
            .find(|(fc, _, _)| *fc <= chunk_no)
            .map(|(_, spc, _)| *spc)
            .unwrap_or(0);
        let mut off = chunk_off;
        for _ in 0..spc {
            if si >= sizes.len() {
                return offsets;
            }
            offsets.push(off);
            off += sizes[si] as u64;
            si += 1;
        }
    }
    offsets
}

fn decrypt_region(
    key: &[u8; 16],
    iv16: &[u8; 16],
    buf: &mut [u8],
    crypt_byte_block: u8,
    skip_byte_block: u8,
) {
    let mut cipher = Aes128Ctr::new(key.into(), iv16.into());
    if crypt_byte_block == 0 && skip_byte_block == 0 {
        cipher.apply_keystream(buf);
        return;
    }
    // Pattern encryption (cens): encrypt crypt_byte_block*16 bytes, skip
    // skip_byte_block*16 bytes, repeat. Keystream only advances over the
    // encrypted runs.
    let crypt = crypt_byte_block as usize * 16;
    let skip = skip_byte_block as usize * 16;
    let mut pos = 0usize;
    while pos < buf.len() {
        let c = crypt.min(buf.len() - pos);
        cipher.apply_keystream(&mut buf[pos..pos + c]);
        pos += c;
        pos += skip.min(buf.len() - pos);
    }
}

pub struct Mp4 {
    pub boxes: Vec<Mp4Box>,
    orig_mdat_offset: u64,
}

impl Mp4 {
    pub fn parse(buf: &[u8]) -> Result<Mp4, String> {
        // Walk the top level once to record mdat's original payload offset.
        let mut pos = 0usize;
        let mut orig_mdat_offset = 0u64;
        while pos + 8 <= buf.len() {
            let size32 = be32(&buf[pos..]) as u64;
            let typ = &buf[pos + 4..pos + 8];
            let (header_len, total) = if size32 == 1 {
                (16usize, be64(&buf[pos + 8..]))
            } else if size32 == 0 {
                (8usize, (buf.len() - pos) as u64)
            } else {
                (8usize, size32)
            };
            if typ == b"mdat" {
                orig_mdat_offset = (pos + header_len) as u64;
            }
            if total < header_len as u64 {
                break;
            }
            pos += total as usize;
        }
        let boxes = Mp4Box::parse_list(buf)?;
        Ok(Mp4 {
            boxes,
            orig_mdat_offset,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for b in &self.boxes {
            b.write_into(&mut out);
        }
        out
    }

    fn mdat_data_mut(&mut self) -> Option<&mut Vec<u8>> {
        for b in &mut self.boxes {
            if &b.typ == b"mdat" {
                if let BoxKind::Leaf { data } = &mut b.kind {
                    return Some(data);
                }
            }
        }
        None
    }

    /// Decrypt all protected tracks for which a key is available.
    ///
    /// `keys_by_kid` maps a 16-byte KID to a 16-byte AES key, and
    /// `keys_by_track` maps a 1-based track id to a key (used by the original
    /// `--key <track>:<hex>` CLI form). Returns the number of tracks decrypted.
    pub fn decrypt(
        &mut self,
        keys_by_kid: &HashMap<[u8; 16], [u8; 16]>,
        keys_by_track: &HashMap<u32, [u8; 16]>,
    ) -> Result<usize, String> {
        let orig_mdat_offset = self.orig_mdat_offset;

        // Take ownership of the moov box so we can mutate trak subtrees while
        // also mutating the mdat buffer.
        let moov_idx = self
            .boxes
            .iter()
            .position(|b| &b.typ == b"moov")
            .ok_or("no moov box")?;
        let mut moov = std::mem::replace(
            &mut self.boxes[moov_idx],
            Mp4Box {
                typ: *b"free",
                kind: BoxKind::Leaf { data: Vec::new() },
            },
        );

        let mut mdat = std::mem::take(self.mdat_data_mut().ok_or("no mdat box")?);
        let mut decrypted_tracks = 0usize;

        if let BoxKind::Container { children, .. } = &mut moov.kind {
            for trak in children.iter_mut().filter(|c| &c.typ == b"trak") {
                match Self::process_trak(
                    trak,
                    &mut mdat,
                    orig_mdat_offset,
                    keys_by_kid,
                    keys_by_track,
                ) {
                    Ok(true) => decrypted_tracks += 1,
                    Ok(false) => {}
                    Err(e) => return Err(e),
                }
            }
        }

        // Put mdat (now decrypted) and moov (now rewritten) back.
        *self.mdat_data_mut().unwrap() = mdat;
        self.boxes[moov_idx] = moov;

        if decrypted_tracks == 0 {
            return Ok(0);
        }

        // Fix chunk offsets: everything before mdat may have changed size.
        let mut new_mdat_offset = 0u64;
        {
            let mut running = 0u64;
            for b in &self.boxes {
                if &b.typ == b"mdat" {
                    let header = if b.body_len() + 8 > u32::MAX as u64 {
                        16
                    } else {
                        8
                    };
                    new_mdat_offset = running + header;
                    break;
                }
                running += b.serialized_len();
            }
        }
        let delta = new_mdat_offset as i64 - orig_mdat_offset as i64;
        if delta != 0 {
            self.shift_chunk_offsets(delta);
        }

        Ok(decrypted_tracks)
    }

    fn shift_chunk_offsets(&mut self, delta: i64) {
        fn visit(b: &mut Mp4Box, delta: i64) {
            match &mut b.kind {
                BoxKind::Container { children, .. } => {
                    for c in children.iter_mut() {
                        visit(c, delta);
                    }
                }
                BoxKind::Leaf { data } => {
                    if &b.typ == b"stco" && data.len() >= 8 {
                        let count = be32(&data[4..8]) as usize;
                        for i in 0..count {
                            let o = 8 + i * 4;
                            if o + 4 > data.len() {
                                break;
                            }
                            let v = be32(&data[o..]) as i64 + delta;
                            data[o..o + 4].copy_from_slice(&(v as u32).to_be_bytes());
                        }
                    } else if &b.typ == b"co64" && data.len() >= 8 {
                        let count = be32(&data[4..8]) as usize;
                        for i in 0..count {
                            let o = 8 + i * 8;
                            if o + 8 > data.len() {
                                break;
                            }
                            let v = be64(&data[o..]) as i64 + delta;
                            data[o..o + 8].copy_from_slice(&(v as u64).to_be_bytes());
                        }
                    }
                }
            }
        }
        for b in &mut self.boxes {
            visit(b, delta);
        }
    }

    /// Returns Ok(true) if the track was decrypted, Ok(false) if it was skipped
    /// (unprotected, or no key available).
    fn process_trak(
        trak: &mut Mp4Box,
        mdat: &mut [u8],
        orig_mdat_offset: u64,
        keys_by_kid: &HashMap<[u8; 16], [u8; 16]>,
        keys_by_track: &HashMap<u32, [u8; 16]>,
    ) -> Result<bool, String> {
        let track_id = trak
            .child(b"tkhd")
            .and_then(|t| t.leaf())
            .and_then(parse_track_id);
        let stbl = match trak
            .child_mut(b"mdia")
            .and_then(|m| m.child_mut(b"minf"))
            .and_then(|m| m.child_mut(b"stbl"))
        {
            Some(s) => s,
            None => return Ok(false),
        };

        // Find the protected sample entry (encv/enca) inside stsd and extract
        // its scheme info.
        let stsd = match stbl.child(b"stsd") {
            Some(s) => s,
            None => return Ok(false),
        };
        let entry_type = {
            let mut found = None;
            if let BoxKind::Container { children, .. } = &stsd.kind {
                for c in children {
                    if &c.typ == b"encv" || &c.typ == b"enca" {
                        found = Some(c.typ);
                        break;
                    }
                }
            }
            match found {
                Some(t) => t,
                None => return Ok(false), // not protected
            }
        };

        // sinf/frma original format, sinf/schi/tenc defaults.
        let (orig_format, tenc) = {
            let entry = stsd.child(&entry_type).unwrap();
            let sinf = entry.child(b"sinf").ok_or("protected entry without sinf")?;
            let frma = sinf
                .child(b"frma")
                .and_then(|f| f.leaf())
                .ok_or("sinf without frma")?;
            if frma.len() < 4 {
                return Err("frma too small".into());
            }
            let mut of = [0u8; 4];
            of.copy_from_slice(&frma[..4]);
            let tenc_data = find_path(sinf, &[b"schi", b"tenc"])
                .and_then(|t| t.leaf())
                .ok_or("sinf without schi/tenc")?;
            (of, parse_tenc(tenc_data)?)
        };

        let key = match keys_by_kid
            .get(&tenc.kid)
            .or_else(|| track_id.and_then(|id| keys_by_track.get(&id)))
        {
            Some(k) => *k,
            None => {
                // We don't have the key for this track; leave it untouched.
                return Ok(false);
            }
        };

        // senc table.
        let senc_data = match stbl.child(b"senc").and_then(|s| s.leaf()) {
            Some(d) => d.to_vec(),
            None => return Err("protected track without senc (progressive CENC expected)".into()),
        };
        let iv_size = tenc.per_sample_iv_size as usize;
        let crypt = parse_senc(&senc_data, iv_size)?;

        // sample geometry.
        let sizes = parse_stsz(
            stbl.child(b"stsz")
                .and_then(|s| s.leaf())
                .ok_or("no stsz")?,
        )?;
        let stsc = parse_stsc(
            stbl.child(b"stsc")
                .and_then(|s| s.leaf())
                .ok_or("no stsc")?,
        )?;
        let chunk_box = stbl
            .child(b"stco")
            .or_else(|| stbl.child(b"co64"))
            .ok_or("no stco/co64")?;
        let chunk_offsets = parse_chunk_offsets(chunk_box)?;
        let offsets = sample_offsets(&sizes, &stsc, &chunk_offsets);

        let n = offsets.len().min(crypt.len()).min(sizes.len());
        for i in 0..n {
            let sample_off = offsets[i];
            let sample_size = sizes[i] as usize;
            let start = (sample_off - orig_mdat_offset) as usize;
            let end = start + sample_size;
            if end > mdat.len() {
                return Err(format!("sample {i} out of mdat bounds"));
            }
            let sample = &mut mdat[start..end];

            // Build the 16-byte counter block: IV bytes then zero padding.
            let mut iv16 = [0u8; 16];
            let ivb = &crypt[i].iv;
            let copy = ivb.len().min(16);
            iv16[..copy].copy_from_slice(&ivb[..copy]);

            let sc = &crypt[i];
            if sc.subsamples.is_empty() {
                decrypt_region(
                    &key,
                    &iv16,
                    sample,
                    tenc.crypt_byte_block,
                    tenc.skip_byte_block,
                );
            } else {
                // One CTR keystream spans the sample; only encrypted ranges
                // consume keystream. Re-create the cipher and walk subsamples.
                let mut cipher = Aes128Ctr::new((&key).into(), (&iv16).into());
                let mut p = 0usize;
                for &(clear, enc) in &sc.subsamples {
                    p += clear as usize; // cleartext: copied as-is
                    let e = enc as usize;
                    if p + e > sample.len() {
                        return Err(format!("subsample {i} out of bounds"));
                    }
                    if tenc.crypt_byte_block == 0 && tenc.skip_byte_block == 0 {
                        cipher.apply_keystream(&mut sample[p..p + e]);
                    } else {
                        // pattern within the encrypted range
                        let crypt_bytes = tenc.crypt_byte_block as usize * 16;
                        let skip_bytes = tenc.skip_byte_block as usize * 16;
                        let mut q = p;
                        let region_end = p + e;
                        while q < region_end {
                            let c = crypt_bytes.min(region_end - q);
                            cipher.apply_keystream(&mut sample[q..q + c]);
                            q += c;
                            q += skip_bytes.min(region_end - q);
                        }
                    }
                    p += e;
                }
            }
        }

        // Rewrite the sample entry to its original format and strip CENC boxes.
        if let Some(entry) = stsd_entry_mut(stbl, &entry_type) {
            entry.typ = orig_format;
            if let BoxKind::Container { children, .. } = &mut entry.kind {
                children.retain(|c| &c.typ != b"sinf");
            }
        }
        if let BoxKind::Container { children, .. } = &mut stbl.kind {
            children.retain(|c| &c.typ != b"senc" && &c.typ != b"saiz" && &c.typ != b"saio");
        }

        Ok(true)
    }
}

fn stsd_entry_mut<'a>(stbl: &'a mut Mp4Box, entry_type: &[u8; 4]) -> Option<&'a mut Mp4Box> {
    let stsd = stbl.child_mut(b"stsd")?;
    if let BoxKind::Container { children, .. } = &mut stsd.kind {
        children.iter_mut().find(|c| &c.typ == entry_type)
    } else {
        None
    }
}
