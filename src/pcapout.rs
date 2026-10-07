//! libpcap (DLT) capture-file writer for the scan spool and `.pcap` export.
//!
//! File format (all multi-byte header fields little-endian):
//! global header: magic `0xa1b2c3d4`, version 2.4, thiszone 0, sigfigs 0,
//! snaplen 65535, linktype 127 (`DLT_IEEE802_11_RADIO`, radiotap). Each
//! packet record: `ts_sec`/`ts_usec` ([`SystemTime::now`]),
//! `incl_len == orig_len == frame.len()`, then the frame bytes.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{LittleEndian as LE, WriteBytesExt};

/// libpcap little-endian magic (as written byte order: d4 c3 b2 a1).
const MAGIC_LE: u32 = 0xa1b2_c3d4;
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;
const SNAPLEN: u32 = 65535;
/// DLT_IEEE802_11_RADIO: frames carry a radiotap header.
const LINKTYPE_RADIOTAP: u32 = 127;

pub struct PcapWriter {
    w: BufWriter<File>,
}

fn write_global_header(w: &mut impl Write) -> io::Result<()> {
    w.write_u32::<LE>(MAGIC_LE)?;
    w.write_u16::<LE>(VERSION_MAJOR)?;
    w.write_u16::<LE>(VERSION_MINOR)?;
    w.write_i32::<LE>(0)?; // thiszone
    w.write_u32::<LE>(0)?; // sigfigs
    w.write_u32::<LE>(SNAPLEN)?;
    w.write_u32::<LE>(LINKTYPE_RADIOTAP)?;
    Ok(())
}

/// Create a new capture file at `path`, truncating any existing content and
/// writing the global header.
pub fn create(path: &Path) -> io::Result<PcapWriter> {
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);
    write_global_header(&mut w)?;
    Ok(PcapWriter { w })
}

/// Open `path` so new frames land after existing ones: an existing
/// non-empty file is opened for append WITHOUT rewriting the global header
/// (spool continuity across restarts); a missing or empty file gets the
/// header written, exactly like [`create`].
pub fn from_path_append(path: &Path) -> io::Result<PcapWriter> {
    let needs_header = match std::fs::metadata(path) {
        Ok(m) => m.len() == 0,
        Err(e) if e.kind() == io::ErrorKind::NotFound => true,
        Err(e) => return Err(e),
    };
    let f = OpenOptions::new().create(true).append(true).open(path)?;
    let mut w = BufWriter::new(f);
    if needs_header {
        write_global_header(&mut w)?;
    }
    Ok(PcapWriter { w })
}

impl PcapWriter {
    /// Append one frame: per-packet record header (current wall-clock
    /// timestamp, `incl_len == orig_len`) followed by the frame bytes.
    pub fn append(&mut self, frame: &[u8]) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let len = frame.len().min(SNAPLEN as usize) as u32;
        self.w.write_u32::<LE>(now.as_secs() as u32)?;
        self.w.write_u32::<LE>(now.subsec_micros())?;
        self.w.write_u32::<LE>(len)?; // incl_len
        self.w.write_u32::<LE>(len)?; // orig_len
        self.w.write_all(&frame[..len as usize])?;
        Ok(())
    }

    /// Flush the buffered frames to disk.
    pub fn finish(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl Drop for PcapWriter {
    fn drop(&mut self) {
        let _ = self.w.flush();
    }
}
