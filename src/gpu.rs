//! GPU-accelerated WPA2-PSK cracker (wgpu compute, see pbkdf2.wgsl) plus a
//! CPU streaming cracker of the same shape.
//!
//! Algorithm: the host computes per candidate the SHA1 midstates for the two
//! HMAC pad prefixes (key = passphrase, salt = ESSID absorbed in the ipad
//! leg) and the first PBKDF2 outputs U1/U2 for both 20-byte blocks. The GPU
//! then executes the remaining 4095 chained HMAC rounds per block and emits
//! T1||T2 (40 bytes): PMK = T1 || T2[0..12]. PTK + MIC are derived per PMK on
//! the host — that is cheap relative to the 4096 HMACs it replaces. For
//! key_ver 3 targets the MIC is AES-CMAC (bus duty: PTK+KCK never leave the
//! host side of the reference implementation).

use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Pack the first 64 message bytes into the 16 FIPS SHA1 message words
/// (big-endian parse, per FIPS 180-1).
fn pack16(bytes: &[u8]) -> [u32; 16] {
    debug_assert!(bytes.len() >= 64);
    let mut out = [0u32; 16];
    for (i, w) in out.iter_mut().enumerate() {
        *w = u32::from_be_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
    }
    out
}

use crate::crypto::{self, CrackTarget};
#[cfg(test)]
use crate::common::MacAddr;

const BATCH: u32 = 1 << 16;
const WORKGROUP_SIZE: u32 = 64;
const ITERATIONS: u32 = 4096;
const U32_PER_CAND_IN: usize = 20; // ipad(5) opad(5) u1(5) u2(5)
const U32_PER_CAND_OUT: usize = 10; // T1(5) T2(5)

const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
const IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

// ---------------------------------------------------------------------------
// Host-side SHA1 midstate helpers (mirror of the WGSL kernel).
// ---------------------------------------------------------------------------

/// One FIPS 180-1 SHA1 compression over exactly one 64-byte block, starting
/// from a 5×u32 state. `block` holds the message words BE-parsed as the
/// standard requires; states and the running chain stay in value domain
/// end-to-end (this is also the WGSL kernel's domain).
fn compress5(state: &mut [u32; 5], block: &[u32; 16]) {
    let mut w = [0u32; 80];
    w[..16].copy_from_slice(block);
    for t in 16..80 {
        let x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
        w[t] = x.rotate_left(1);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);
    for (t, &wt) in w.iter().enumerate() {
        let f = match t {
            0..=19 => (b & c) | (!b & d),
            20..=39 | 60..=79 => b ^ c ^ d,
            _ => (b & c) | (b & d) | (c & d),
        };
        let k = K[t / 20];
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(wt);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// Finalize a two-block SHA1 message given the state after block 1: place
/// the tail, append padding/bit-length for the total (64 + tail.len()) byte
/// message, compress once. Returns the 5-word state (the FIPS digest words).
fn finalize_64(state_after_b1: &[u32; 5], tail: &[u8]) -> [u32; 5] {
    debug_assert!(tail.len() < 56);
    let total_len = (64 + tail.len()) as u64;
    let mut blk = [0u8; 64];
    blk[..tail.len()].copy_from_slice(tail);
    blk[tail.len()] = 0x80;
    blk[56..64].copy_from_slice(&(total_len * 8).to_be_bytes());
    let mut st = *state_after_b1;
    compress5(&mut st, &pack16(&blk));
    st
}

/// First PBKDF2 block digest for a candidate: U_idx = HMAC(P, salt ||
/// INT32BE(idx)), using precomputed pad midstates. Inner leg message is
/// (P^ipad) || salt || BE32(idx) (64 + salt.len() + 4 bytes), outer leg is
/// (P^opad) || inner_digest (84 bytes, 672 bits).
fn hmac_first(ipad: &[u32; 5], opad: &[u32; 5], salt: &[u8], block_idx: u32) -> [u32; 5] {
    let mut tail = [0u8; 68];
    tail[..salt.len()].copy_from_slice(salt);
    tail[salt.len()..salt.len() + 4].copy_from_slice(&block_idx.to_be_bytes());
    let inner = finalize_64(ipad, &tail[..salt.len() + 4]);

    let mut outer_blk = [0u32; 16];
    outer_blk[..5].copy_from_slice(&inner);
    outer_blk[5] = 0x8000_0000;
    outer_blk[15] = 672;
    let mut st = *opad;
    compress5(&mut st, &outer_blk);
    st
}

/// Mirror of the WGSL `hmac_mid`: one chained HMAC round (two compresses)
/// over the 20-byte value `u` given the pad midstates.
fn hmac_midstate_host(ipad: &[u32; 5], opad: &[u32; 5], u: &[u32; 5]) -> [u32; 5] {
    let mut msg = [0u32; 16];
    msg[..5].copy_from_slice(u);
    msg[5] = 0x8000_0000;
    msg[15] = 672;

    let mut st = *ipad;
    compress5(&mut st, &msg);

    let mut outer = [0u32; 16];
    outer[..5].copy_from_slice(&st);
    outer[5] = 0x8000_0000;
    outer[15] = 672;

    let mut st2 = *opad;
    compress5(&mut st2, &outer);
    st2
}

/// Per-candidate kernel inputs for one passphrase.
fn candidate_inputs(pass: &[u8], salt: &[u8]) -> [u32; U32_PER_CAND_IN] {
    debug_assert!((8..=63).contains(&pass.len()));

    let mut ipad_blk = [0x36u8; 64];
    let mut opad_blk = [0x5cu8; 64];
    for (i, &b) in pass.iter().enumerate() {
        ipad_blk[i] ^= b;
        opad_blk[i] ^= b;
    }

    let mut ipad = IV;
    let mut opad = IV;
    compress5(&mut ipad, &pack16(&ipad_blk));
    compress5(&mut opad, &pack16(&opad_blk));

    // U_i = HMAC(P, salt || INT32BE(i)): inner leg via the ipad midstate,
    // outer leg one compress over the opad midstate (also 84-byte total
    // message → bit length 672, same layout as the chained rounds).
    let u1 = hmac_first(&ipad, &opad, salt, 1);
    let u2 = hmac_first(&ipad, &opad, salt, 2);

    let mut out = [0u32; U32_PER_CAND_IN];
    out[..5].copy_from_slice(&ipad);
    out[5..10].copy_from_slice(&opad);
    out[10..15].copy_from_slice(&u1);
    out[15..20].copy_from_slice(&u2);
    out
}

/// Finish the two PBKDF2 blocks for one candidate entirely on the CPU
/// (reference + fallback path).
fn pmk_via_midstates(inputs: &[u32; U32_PER_CAND_IN]) -> [u8; 32] {
    let mut ipad = [0u32; 5];
    let mut opad = [0u32; 5];
    let mut u1 = [0u32; 5];
    let mut u2 = [0u32; 5];
    ipad.copy_from_slice(&inputs[..5]);
    opad.copy_from_slice(&inputs[5..10]);
    u1.copy_from_slice(&inputs[10..15]);
    u2.copy_from_slice(&inputs[15..20]);

    let mut t1 = u1;
    let mut t2 = u2;
    for _ in 1..ITERATIONS {
        u1 = hmac_midstate_host(&ipad, &opad, &u1);
        for i in 0..5 {
            t1[i] ^= u1[i];
        }
        u2 = hmac_midstate_host(&ipad, &opad, &u2);
        for i in 0..5 {
            t2[i] ^= u2[i];
        }
    }

    let mut pmk_bytes = [0u8; 32];
    for i in 0..5 {
        pmk_bytes[i * 4..i * 4 + 4].copy_from_slice(&t1[i].to_be_bytes());
    }
    for i in 0..3 {
        pmk_bytes[20 + i * 4..20 + i * 4 + 4].copy_from_slice(&t2[i].to_be_bytes());
    }
    pmk_bytes
}

// ---------------------------------------------------------------------------
// GPU cracker
// ---------------------------------------------------------------------------

pub struct GpuCracker {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    layout: wgpu::BindGroupLayout,
    name: String,
    batch: u32,
}

impl GpuCracker {
    /// None when no suitable adapter/device exists (caller falls back to the
    /// CPU cracker).
    pub fn try_new() -> Option<Self> {
        let instance =
            wgpu::Instance::new(wgpu::InstanceDescriptor::new_without_display_handle());
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
            compatible_surface: None,
            apply_limit_buckets: false,
        }))
        .ok()?;
        let info = adapter.get_info();
        let limits = adapter.limits();
        // Need storage buffers of BATCH × 80 B in and BATCH × 40 B out.
        let in_bytes = u64::from(BATCH) * (U32_PER_CAND_IN as u64) * 4;
        let out_bytes = u64::from(BATCH) * (U32_PER_CAND_OUT as u64) * 4;
        if u64::from(limits.max_storage_buffer_binding_size) < in_bytes
            || u64::from(limits.max_storage_buffer_binding_size) < out_bytes
            || limits.max_buffer_size < in_bytes.max(out_bytes)
        {
            return None;
        }

        let desc = wgpu::DeviceDescriptor {
            label: Some("wifilab-pbkdf2"),
            required_features: wgpu::Features::empty(),
            required_limits: wgpu::Limits::default(),
            experimental_features: wgpu::ExperimentalFeatures::disabled(),
            memory_hints: wgpu::MemoryHints::Performance,
            trace: wgpu::Trace::Off,
        };
        let (device, queue) = pollster::block_on(adapter.request_device(&desc)).ok()?;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("pbkdf2.wgsl"),
            source: wgpu::ShaderSource::Wgsl(include_str!("pbkdf2.wgsl").into()),
        });

        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("pbkdf2-layout"),
            entries: &[
                // params uniform
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: NonZeroU64::new(16),
                    },
                    count: None,
                },
                // midstates in
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                // outputs out
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("pbkdf2-pipeline-layout"),
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("pbkdf2-pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache: None,
        });

        Some(GpuCracker {
            device,
            queue,
            pipeline,
            layout,
            name: format!("{} ({:?})", info.name, info.backend),
            batch: BATCH,
        })
    }

    pub fn device_name(&self) -> String {
        self.name.clone()
    }

    /// Measured full-attack throughput for progress reporting (4096-iteration
    /// batches). Runs 4 batches through `pmk_batch_gpu` and returns H/s.
    #[cfg(test)]
    fn measured_hps(&self) -> Option<f64> {
        let pass: Vec<u8> = b"benchmk1".to_vec();
        let salt = b"benchmark-ssid";
        let mut inputs = Vec::with_capacity(self.batch as usize * U32_PER_CAND_IN);
        for i in 0..self.batch as usize {
            let mut w = pass.clone();
            w[0] = b'a' + (i % 26) as u8;
            inputs.extend_from_slice(&candidate_inputs(&w, salt));
        }
        // Warm-up batch: covers one-time SPIR-V->ISA compile & memory init.
        self.run_kernel(&inputs)?;
        const BATCHES: u32 = 8;
        let t0 = Instant::now();
        let mut ok = true;
        for _ in 0..BATCHES {
            let mut inp = inputs.clone();
            inp[0] = inp[0].wrapping_add(1);
            ok &= self.run_kernel(&inp).is_some();
        }
        if !ok {
            return None;
        }
        let secs = t0.elapsed().as_secs_f64();
        Some(self.batch as f64 * f64::from(BATCHES) / secs)
    }

    /// Run one kernel batch over `inputs` (n×20 u32, on the wire as u32 LE).
    /// Returns the n×10 u32 output words, or None on device-lost/hang.
    fn run_kernel(&self, inputs: &[u32]) -> Option<Vec<u32>> {
        let n = inputs.len() / U32_PER_CAND_IN;
        if n == 0 {
            return Some(Vec::new());
        }

        let in_bytes = (inputs.len() * 4) as u64;
        let out_u32 = n * U32_PER_CAND_OUT;
        let out_bytes = (out_u32 * 4) as u64;

        let in_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("midstates"),
            size: in_bytes.max(16),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let out_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("t1t2"),
            size: out_bytes.max(16),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let read_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("readback"),
            size: out_bytes.max(16),
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let param_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("params"),
            size: 16,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let flags: u32 = ITERATIONS << 1;
        let params: [u32; 4] = [flags, 0, 0, 0];
        self.queue
            .write_buffer(&param_buf, 0, &u32s_as_bytes(&params));
        let in_bytes_vec = u32s_as_bytes(inputs);
        self.queue.write_buffer(&in_buf, 0, &in_bytes_vec);

        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("pbkdf2-bg"),
            layout: &self.layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: param_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: in_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: out_buf.as_entire_binding(),
                },
            ],
        });

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("pbkdf2-encoder"),
            });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("pbkdf2-pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(n.div_ceil(WORKGROUP_SIZE as usize) as u32, 1, 1);
        }
        encoder.copy_buffer_to_buffer(&out_buf, 0, &read_buf, 0, out_bytes);
        let sub = self.queue.submit([encoder.finish()]);

        // Wait for the shader with timeout; a hung/compute-heavy dispatch is
        // reported so the caller can halve the batch.
        let (tx, rx) = std::sync::mpsc::channel();
        read_buf
            .slice(..)
            .map_async(wgpu::MapMode::Read, move |res| {
                let _ = tx.send(res);
            });

        let mut waited = Duration::ZERO;
        let step = Duration::from_millis(50);
        let limit = Duration::from_secs(30);
        loop {
            match self.device.poll(wgpu::PollType::Wait {
                submission_index: Some(sub.clone()),
                timeout: Some(step),
            }) {
                Ok(_) | Err(wgpu::PollError::Timeout) => {
                    if let Ok(res) = rx.try_recv() {
                        match res {
                            Ok(()) => break,
                            Err(e) => {
                                tracing::warn!("map_async failed: {e}");
                                read_buf.unmap();
                                return None;
                            }
                        }
                    }
                    waited += step;
                    if waited >= limit {
                        tracing::warn!("gpu dispatch timed out after {limit:?}");
                        return None;
                    }
                }
                Err(e) => {
                    tracing::warn!("device poll error: {e}");
                    return None;
                }
            }
        }

        let view = read_buf.slice(..).get_mapped_range().ok()?;
        let mut out = Vec::with_capacity(out_u32);
        for chunk in view[..(out_u32 * 4)].chunks_exact(4) {
            out.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        drop(view);
        read_buf.unmap();
        Some(out)
    }

    /// Compute PMKs for a word batch. Halves the batch size once on
    /// device-lost/timeout; on a repeated failure returns None.
    fn pmk_batch_gpu(&self, words: &[Vec<u8>], salt: &[u8]) -> Option<Vec<[u8; 32]>> {
        let mut cur: Vec<Vec<u8>> = words.to_vec();
        let mut attempts = 0u8;
        loop {
            let mut inputs = Vec::with_capacity(cur.len() * U32_PER_CAND_IN);
            for w in &cur {
                inputs.extend_from_slice(&candidate_inputs(w, salt));
            }
            if let Some(out) = self.run_kernel(&inputs) {
                return Some(assemble_pmks(&out));
            }
            attempts += 1;
            if attempts > 1 || cur.len() == 1 {
                return None;
            }
            let half = cur.len().div_ceil(2);
            cur = cur[..half].to_vec();
        }
    }

    /// Stream `words` through the GPU, calling `progress(done, hps)` once per
    /// dispatched batch (also when a partial final batch ran). Honors `stop`
    /// between batches. Returns the passphrase on MIC match.
    pub fn crack(
        &self,
        target: &CrackTarget,
        words: &mut dyn Iterator<Item = Vec<u8>>,
        progress: &mut dyn FnMut(u64, f64),
        stop: &Arc<AtomicBool>,
    ) -> Option<String> {
        if matches!(target, CrackTarget::Handshake(h) if h.eapol_m2.len() < 99) {
            return None;
        }
        let salt = target.essid().as_bytes();
        let mut done = 0u64;
        let started = Instant::now();
        let mut batch_cap = self.batch as usize;

        loop {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(batch_cap);
            while batch.len() < batch_cap {
                match words.next() {
                    Some(w) => batch.push(w),
                    None => break,
                }
            }
            if batch.is_empty() {
                return None;
            }

            let pmks = self.pmk_batch_gpu(&batch, salt)?;
            // If the PMK batch shrunk because of a device hiccup the tail
            // candidates are re-attempted below; keep bookkeeping accurate by
            // scanning only what came back and re-queueing the rest.
            let checked = pmks.len();
            for (i, k) in pmks.iter().enumerate() {
                done += 1;
                if target_matches(target, k) {
                    return String::from_utf8(batch[i].clone()).ok();
                }
            }
            let secs = started.elapsed().as_secs_f64().max(1e-6);
            progress(done, done as f64 / secs);

            if checked < batch.len() {
                // Device hiccup path: retry the remaining words in smaller
                // chunks before continuing the stream.
                let rest = batch[checked..].to_vec();
                for chunk in rest.chunks(batch_cap.div_ceil(2).max(1)) {
                    if stop.load(Ordering::Relaxed) {
                        return None;
                    }
                    let pmks = self.pmk_batch_gpu(chunk, salt)?;
                    for (i, k) in pmks.iter().enumerate() {
                        done += 1;
                        if target_matches(target, k) {
                            return String::from_utf8(chunk[i].clone()).ok();
                        }
                    }
                    let secs = started.elapsed().as_secs_f64().max(1e-6);
                    progress(done, done as f64 / secs);
                }
                batch_cap = batch_cap.div_ceil(2).max(1024);
            }
        }
    }
}

/// Little-endian byte serialization of a u32 slice for queue.write_buffer.
/// The kernel reads raw u32s; on this CPU (x86-64, LE) this matches memory
/// layout, and serializing keeps the wire format explicit for any host.
fn u32s_as_bytes(v: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for &w in v {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn assemble_pmks(out: &[u32]) -> Vec<[u8; 32]> {
    let n = out.len() / U32_PER_CAND_OUT;
    let mut pmks = Vec::with_capacity(n);
    for c in 0..n {
        let mut pmk = [0u8; 32];
        let row = &out[c * U32_PER_CAND_OUT..(c + 1) * U32_PER_CAND_OUT];
        for i in 0..8 {
            pmk[i * 4..i * 4 + 4].copy_from_slice(&row[i].to_be_bytes());
        }
        pmks.push(pmk);
    }
    pmks
}

/// MIC/PMKID check of one PMK against the target.
fn target_matches(target: &CrackTarget, k: &[u8; 32]) -> bool {
    match target {
        CrackTarget::Handshake(h) => {
            let dk = crypto::ptk(k, &h.ap, &h.client, &h.anonce, &h.snonce);
            let m = crypto::mic(&dk, &h.eapol_m2, h.key_ver);
            crypto::ct_eq16(&m, h.mic())
        }
        CrackTarget::Pmkid(p) => {
            let dig = crypto::pmkid_hash(k, &p.ap, &p.client);
            crypto::ct_eq16(&dig, &p.pmkid)
        }
    }
}

// ---------------------------------------------------------------------------
// CPU cracker (reference-fallback path)
// ---------------------------------------------------------------------------

/// Streaming CPU cracker with the same contract as `GpuCracker::crack`.
pub fn cpu_crack(
    target: &CrackTarget,
    words: &mut dyn Iterator<Item = Vec<u8>>,
    progress: &mut dyn FnMut(u64, f64),
    stop: &Arc<AtomicBool>,
) -> Option<String> {
    if matches!(target, CrackTarget::Handshake(h) if h.eapol_m2.len() < 99) {
        return None;
    }
    let salt = target.essid().as_bytes();
    let mut done = 0u64;
    let started = Instant::now();
    const CPU_BATCH: usize = 512;

    loop {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(CPU_BATCH);
        while batch.len() < CPU_BATCH {
            match words.next() {
                Some(w) => batch.push(w),
                None => break,
            }
        }
        if batch.is_empty() {
            return None;
        }
        for w in &batch {
            done += 1;
            let key = crypto::pmk(w, salt);
            if target_matches(target, &key) {
                return String::from_utf8(w.clone()).ok();
            }
        }
        let secs = started.elapsed().as_secs_f64().max(1e-6);
        progress(done, done as f64 / secs);
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    fn build_eapol_m2(key_ver: u8, snonce: &[u8; 32], replay: u64) -> Vec<u8> {
        let mut f = Vec::with_capacity(99);
        f.push(0x02);
        f.push(0x03);
        f.extend_from_slice(&95u16.to_be_bytes());
        f.push(0x02);
        let info: u16 = 0x0100 | 0x0080 | (key_ver as u16 & 0x7);
        f.extend_from_slice(&info.to_be_bytes());
        f.extend_from_slice(&16u16.to_be_bytes());
        f.extend_from_slice(&replay.to_be_bytes());
        f.extend_from_slice(snonce);
        f.extend_from_slice(&[0u8; 16]);
        f.extend_from_slice(&[0u8; 8]);
        f.extend_from_slice(&[0u8; 8]);
        f.extend_from_slice(&[0u8; 16]);
        f.extend_from_slice(&0u16.to_be_bytes());
        f
    }

    fn synthetic_target(ssid: &str, pass: &[u8], key_ver: u8) -> CrackTarget {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        let sta = "11:22:33:44:55:66".parse::<MacAddr>().unwrap();
        let anonce: [u8; 32] = [0x5a; 32];
        let snonce: [u8; 32] = [0xc3; 32];
        let key = crypto::pmk(pass, ssid.as_bytes());
        let dk = crypto::ptk(&key, &ap, &sta, &anonce, &snonce);
        let frame = build_eapol_m2(key_ver, &snonce, 1);
        let m = crypto::mic(&dk, &frame, key_ver);
        CrackTarget::Handshake(crate::common::HandshakeCapture::new(
            ap,
            sta,
            ssid.to_string(),
            anonce,
            snonce,
            m,
            frame,
            key_ver,
        ))
    }

    #[test]
    fn host_midstate_matches_pbkdf2() {
        // candidate_inputs + pmk_via_midstates must equal crypto's
        // PBKDF2-HMAC-SHA1 (itself pinned to RFC 6070 + the IEEE wpa vector
        // in crypto::tests) for arbitrary passphrases and salts.
        for pass in [&b"password1"[..], b"sup3r-secret", &vec![b'x'; 63][..], b"87654321"] {
            for ssid in [&b"IEEE"[..], b"parafin", b"", b"long-ssid-0123456789"] {
                let inputs = candidate_inputs(pass, ssid);
                let got = pmk_via_midstates(&inputs);
                let mut dk = [0u8; 40];
                crypto::pbkdf2_hmac_sha1(pass, ssid, 4096, &mut dk);
                assert_eq!(&got[..], &dk[..32], "pass={pass:?} ssid={ssid:?}");
            }
        }
    }

    #[test]
    fn gpu_available_and_pmk_matches() {
        let Some(crk) = GpuCracker::try_new() else {
            eprintln!("no GPU adapter, skipping");
            return;
        };
        let salt = b"parafin";
        let words: Vec<Vec<u8>> = (0..16)
            .map(|i| format!("cand{:06}", i).into_bytes())
            .collect();
        let mut inputs = Vec::new();
        for w in &words {
            inputs.extend_from_slice(&candidate_inputs(w, salt));
        }
        let out = crk.run_kernel(&inputs).expect("kernel must complete");
        let pmks = assemble_pmks(&out);
        for (w, k) in words.iter().zip(pmks.iter()) {
            let mut dk = [0u8; 40];
            crypto::pbkdf2_hmac_sha1(w, salt, 4096, &mut dk);
            assert_eq!(&k[..], &dk[..32], "GPU PMK mismatch for {w:?}");
            // Also bit-exact vs the RFC-anchored crypto::pmk.
            assert_eq!(k, &crypto::pmk(w, salt), "crypto::pmk mismatch for {w:?}");
        }
    }

    #[test]
    fn gpu_finds_planted_pass() {
        let Some(crk) = GpuCracker::try_new() else {
            eprintln!("no GPU adapter, skipping");
            return;
        };
        eprintln!("gpu device: {}", crk.device_name());
        let pass = b"sup3r-secret";
        let target = synthetic_target("parafin", pass, 2);

        const TOTAL: usize = 5000;
        let mut idx = 0usize;
        let words: Vec<Vec<u8>> = (0..TOTAL)
            .map(|_| {
                idx += 1;
                if idx == 3800 {
                    pass.to_vec()
                } else {
                    format!("w{:07}", idx).into_bytes()
                }
            })
            .collect();
        let mut it = words.into_iter();
        let stop = Arc::new(AtomicBool::new(false));
        let (mut last_done, mut last_hps) = (0u64, 0f64);
        let found = crk.crack(
            &target,
            &mut it,
            &mut |d, h| {
                last_done = d;
                last_hps = h;
            },
            &stop,
        );
        assert_eq!(found.as_deref(), Some("sup3r-secret"));
        // crack returns immediately at the match, possibly before the
        // batch-end progress tick, so progress may be anything ≤ 65536.
        assert!(last_done <= 65536, "progress reported {last_done}");
        assert!(last_hps >= 0.0);
    }

    #[test]
    fn gpu_agrees_with_crypto_verify_on_synthetic() {
        let Some(_crk) = GpuCracker::try_new() else {
            eprintln!("no GPU adapter, skipping");
            return;
        };
        // The GPU path (kernel) for a batch containing the right pass must
        // identify exactly the candidates crypto::verify accepts.
        let crk = _crk;
        let pass = b"sup3r-secret";
        let target = synthetic_target("parafin", pass, 2);
        let cands: Vec<Vec<u8>> = (0..64)
            .map(|i| if i == 33 { pass.to_vec() } else { format!("zz{:07}", i).into_bytes() })
            .collect();
        let mut inputs = Vec::new();
        for w in &cands {
            inputs.extend_from_slice(&candidate_inputs(w, b"parafin"));
        }
        let out = crk.run_kernel(&inputs).expect("kernel");
        let pmks = assemble_pmks(&out);
        let mut hits = 0;
        for (w, k) in cands.iter().zip(pmks.iter()) {
            let gpu_hit = target_matches(&target, k);
            let cpu_hit = crypto::verify(&target, w);
            assert_eq!(gpu_hit, cpu_hit, "disagreement on {w:?}");
            hits += gpu_hit as usize;
        }
        assert_eq!(hits, 1);
    }

    #[test]
    fn pmk64_benchmark_hps() {
        let Some(crk) = GpuCracker::try_new() else {
            eprintln!("no GPU adapter, skipping benchmark");
            return;
        };
        let hps = crk.measured_hps().expect("kernel must succeed");
        eprintln!(
            "GPU PBKDF2-WPA2 throughput on {}: {:.0} H/s",
            crk.device_name(),
            hps
        );
        assert!(hps > 1000.0, "suspiciously slow: {hps} H/s");
    }

    #[test]
    fn cpu_crack_finds_pass() {
        let pass = b"sup3r-secret";
        let target = synthetic_target("parafin", pass, 2);
        let mut idx = 0usize;
        let words: Vec<Vec<u8>> = (0..500)
            .map(|_| {
                idx += 1;
                if idx == 300 { pass.to_vec() } else { format!("cpu{:07}", idx).into_bytes() }
            })
            .collect();
        let mut it = words.into_iter();
        let stop = Arc::new(AtomicBool::new(false));
        let found = cpu_crack(&target, &mut it, &mut |_, _| {}, &stop);
        assert_eq!(found.as_deref(), Some("sup3r-secret"));
    }

    #[test]
    fn cpu_crack_pmkid() {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        let sta = "11:22:33:44:55:66".parse::<MacAddr>().unwrap();
        let key = crypto::pmk(b"hunter2!!", b"parafin");
        let target = CrackTarget::Pmkid(crate::common::PmkidCapture {
            ap,
            client: sta,
            essid: "parafin".to_string(),
            pmkid: crypto::pmkid_hash(&key, &ap, &sta),
        });
        let words: Vec<Vec<u8>> = vec![b"nope-nope".to_vec(), b"hunter2!!".to_vec()];
        let mut it = words.into_iter();
        let stop = Arc::new(AtomicBool::new(false));
        let found = cpu_crack(&target, &mut it, &mut |_, _| {}, &stop);
        assert_eq!(found.as_deref(), Some("hunter2!!"));
    }

    #[test]
    fn stop_flag_short_circuits() {
        let pass = b"sup3r-secret";
        let target = synthetic_target("parafin", pass, 2);
        let words: Vec<Vec<u8>> = (0..2000).map(|i| format!("zz{:07}", i).into_bytes()).collect();
        let mut it = words.into_iter();
        let stop = Arc::new(AtomicBool::new(true));
        assert!(cpu_crack(&target, &mut it, &mut |_, _| {}, &stop).is_none());
        if let Some(crk) = GpuCracker::try_new() {
            let words2: Vec<Vec<u8>> = (0..2000).map(|i| format!("zz{:07}", i).into_bytes()).collect();
            let mut it2 = words2.into_iter();
            assert!(crk.crack(&target, &mut it2, &mut |_, _| {}, &stop).is_none());
        }
    }
}

