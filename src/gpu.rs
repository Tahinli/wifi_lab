//! GPU-accelerated WPA2-PSK cracker (wgpu compute, see pbkdf2.wgsl) plus a
//! CPU streaming cracker of the same shape.
//!
//! Full-pipeline architecture: the host packs raw candidate bytes only.
//! The kernel itself derives the HMAC pad midstates (2 compressions),
//! computes U1/U2 from host-precomputed padded salt messages, runs the
//! 4095-iteration chained HMAC loop (registers only), and performs the
//! verify EPILOGUE on-device (PTK-KCK HMAC + EAPOL MIC compare, or PMKID
//! compare). Per batch the host reads back a 16-byte hit slot instead of
//! batch×40B of PMKs — the previous midstate/upload + CPU MIC phases were
//! the pipeline's throughput ceiling.
//!
//! Targets whose MIC is AES-CMAC (key_ver 3) are not expressible in this
//! shader; [`gpu_verifiable`] routes them to the CPU cracker.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::crypto::{self, CrackTarget};
use crate::rainbow;
#[cfg(test)]
use crate::common::MacAddr;

/// Target view with the candidate-invariant parts precomputed — the MIC
/// zeroing of the EAPOL frame is fixed for the whole run ([`crypto::mic`]
/// re-copies and re-zeroes the frame per call, which is measurable at
/// 65536 candidates per batch).
pub(crate) enum PreparedTarget<'a> {
    Handshake(&'a crate::common::HandshakeCapture, Vec<u8>),
    Pmkid(&'a crate::common::PmkidCapture),
}

/// Prepare once per crack run (CPU + rainbow paths).
pub(crate) fn prepare_target(target: &CrackTarget) -> PreparedTarget<'_> {
    match target {
        CrackTarget::Handshake(h) => {
            PreparedTarget::Handshake(h, crypto::zeroed_eapol(&h.eapol_m2))
        }
        CrackTarget::Pmkid(p) => PreparedTarget::Pmkid(p),
    }
}

/// MIC/PMKID check of one PMK against a [`PreparedTarget`].
pub(crate) fn prepared_matches(prepared: &PreparedTarget, k: &[u8; 32]) -> bool {
    match prepared {
        PreparedTarget::Handshake(h, zeroed) => {
            let dk = crypto::ptk(k, &h.ap, &h.client, &h.anonce, &h.snonce);
            let m = crypto::mic_on_zeroed(&dk, zeroed, h.key_ver);
            crypto::ct_eq16(&m, h.mic())
        }
        PreparedTarget::Pmkid(p) => {
            let dig = crypto::pmkid_hash(k, &p.ap, &p.client);
            crypto::ct_eq16(&dig, &p.pmkid)
        }
    }
}

const BATCH: u32 = 1 << 16;
const WORKGROUP_SIZE: u32 = 256;
const ITERATIONS: u32 = 4096;
/// Candidate wire format: password bytes packed BE into 16 u32 (zero pad).
const U32_PER_CAND_IN: usize = 16;
/// PMK rows for the pmk_out (rainbow-build) entry: 8 words PMK + 2 pad.
const U32_PER_CAND_OUT: usize = 10;
/// Hit slot: [flag, gid] + pad.
const HIT_U32: usize = 4;
// Params layout (u32 words) — MUST mirror `struct Params` in pbkdf2.wgsl.
const P_HEADER: usize = 8;
const P_MSGS: usize = 32; // u1_msg || u2_msg
const P_BLK: usize = 48;
const PARAM_U32: usize = P_HEADER + P_MSGS + 2 * P_BLK + 4;

/// Everything the kernel needs per crack run: the params words, built
/// once at target-prepare time (only word 4, the batch candidate count,
/// varies per dispatch).
pub(crate) struct GpuTargetCtx {
    params: Vec<u32>,
}

impl GpuTargetCtx {
    /// Params words for one dispatch (`n` = candidate count). Clone of
    /// the per-run template: 560 B, negligible per batch.
    fn params_words(&self, n: u32) -> Vec<u32> {
        let mut v = self.params.clone();
        v[4] = n;
        v
    }
}

/// Big-endian pack of `bytes` into u32 words (SHA1's message-word view).
fn be_words(bytes: &[u8], out: &mut [u32]) {
    for (i, w) in out.iter_mut().enumerate() {
        let mut word = 0u32;
        for (j, &b) in bytes.iter().skip(4 * i).take(4).enumerate() {
            word |= (b as u32) << (24 - 8 * j);
        }
        *w = word;
    }
}

/// FIPS-pad an HMAC message (following the implicit 64-byte pad prefix)
/// and pack into BE 64-byte-block words; returns (words, block count).
fn padded_blocks(msg: &[u8]) -> (Vec<u32>, u32) {
    let total_bits = ((64 + msg.len()) as u64) * 8;
    let mut v = msg.to_vec();
    v.push(0x80);
    while v.len() % 64 != 56 {
        v.push(0);
    }
    v.extend_from_slice(&total_bits.to_be_bytes());
    let n_blocks = v.len() / 64;
    let mut words = vec![0u32; n_blocks * 16];
    be_words(&v, &mut words);
    (words, n_blocks as u32)
}

/// U-block message for PBKDF2: salt || INT32BE(idx), padded whole. Must
/// fit one block (salt ≤ 51 bytes, incl. the 9 padding bytes).
fn u_msg(salt: &[u8], idx: u32) -> [u32; 16] {
    let mut m = Vec::with_capacity(salt.len() + 4);
    m.extend_from_slice(salt);
    m.extend_from_slice(&idx.to_be_bytes());
    let (words, n) = padded_blocks(&m);
    debug_assert_eq!(n, 1, "salt must fit one SHA1 block");
    let mut out = [0u32; 16];
    out.copy_from_slice(&words[..16]);
    out
}

/// Build the kernel verify context. None when the target is not
/// expressible in the SHA1-only shader: AES-CMIC handshake (key_ver 3),
/// truncated frame, or overlong ESSID (> 51 bytes — spills the U block).
pub(crate) fn gpu_ctx(target: &CrackTarget) -> Option<GpuTargetCtx> {
    let salt = target.essid().as_bytes();
    if salt.len() > 51 {
        return None;
    }
    let u1_msg = u_msg(salt, 1);
    let u2_msg = u_msg(salt, 2);
    let mut blk1 = [0u32; 48];
    let mut blk2 = [0u32; 48];
    let mut mic = [0u32; 4];
    let (is_pmkid, n_blk1, n_blk2) = match target {
        CrackTarget::Pmkid(p) => {
            // PMKID = HMAC-SHA1-128(PMK, "PMK Name" || ap || sta)[0..16].
            let mut msg = Vec::with_capacity(8 + 6 + 6);
            msg.extend_from_slice(b"PMK Name");
            msg.extend_from_slice(&p.ap.0);
            msg.extend_from_slice(&p.client.0);
            let (w, n) = padded_blocks(&msg);
            blk1[..w.len()].copy_from_slice(&w);
            be_words(&p.pmkid, &mut mic);
            (1, n, 0)
        }
        CrackTarget::Handshake(h) => {
            if h.key_ver == 3 || h.eapol_m2.len() < 99 {
                return None;
            }
            // blk1: PRF message round 1 = prf_stem || 0x01 → KCK.
            let mut prf = crypto::prf_stem(&h.ap, &h.client, &h.anonce, &h.snonce);
            prf.push(0x01);
            let (w1, n1) = padded_blocks(&prf);
            blk1[..w1.len()].copy_from_slice(&w1);
            // blk2: zeroed EAPOL frame (MIC message; 2..3 blocks).
            let zeroed = crypto::zeroed_eapol(&h.eapol_m2);
            let (w2, n2) = padded_blocks(&zeroed);
            blk2[..w2.len()].copy_from_slice(&w2);
            be_words(h.mic(), &mut mic);
            (0, n1, n2)
        }
    };
    let mut params = vec![0u32; PARAM_U32];
    params[0] = ITERATIONS << 1;
    params[1] = is_pmkid;
    params[2] = n_blk1;
    params[3] = n_blk2;
    params[P_HEADER..P_HEADER + 16].copy_from_slice(&u1_msg);
    params[P_HEADER + 16..P_HEADER + 32].copy_from_slice(&u2_msg);
    params[P_HEADER + P_MSGS..P_HEADER + P_MSGS + P_BLK].copy_from_slice(&blk1);
    params[P_HEADER + P_MSGS + P_BLK..P_HEADER + P_MSGS + 2 * P_BLK].copy_from_slice(&blk2);
    params[PARAM_U32 - 4..].copy_from_slice(&mic);
    Some(GpuTargetCtx { params })
}

/// Whether the GPU shader can verify this target (SHA1-family only; the
/// AES-CMAC key_ver 3 path stays on the CPU cracker).
pub(crate) fn gpu_verifiable(target: &CrackTarget) -> bool {
    gpu_ctx(target).is_some()
}

/// Pack raw passphrases into the kernel wire format (BE words, zero pad).
fn pack_candidates(words: &[Vec<u8>]) -> Vec<u32> {
    let mut out = vec![0u32; words.len() * U32_PER_CAND_IN];
    for (w, dst) in words.iter().zip(out.chunks_exact_mut(U32_PER_CAND_IN)) {
        be_words(w, dst);
    }
    out
}

/// One in-flight kernel dispatch. Buffers live in the pool; the handle
/// carries what waiting/returning needs.
struct PendingKernel {
    read_buf: wgpu::Buffer,
    slot: usize,
    rx: std::sync::mpsc::Receiver<Result<(), wgpu::BufferAsyncError>>,
    sub: wgpu::SubmissionIndex,
    read_u32: usize,
}

/// Returns a pool slot on drop, on ANY exit path of `wait_kernel`.
struct SlotGuard<'a> {
    pool: &'a std::cell::RefCell<Option<KernelPool>>,
    slot: usize,
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.borrow_mut().as_mut() {
            pool.free.push(self.slot);
        }
    }
}

/// One persistent set of dispatch buffers + bind group, sized for a full
/// batch (the 16-byte param/hit writes per batch are near-free).
struct KernelBufs {
    in_buf: wgpu::Buffer,
    out_buf: wgpu::Buffer,
    hit_buf: wgpu::Buffer,
    read_buf: wgpu::Buffer,
    param_buf: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
}

/// Free-slot allocator over persistent [`KernelBufs`]; starts with 2
/// slots (pipeline depth), grows on demand rather than failing.
struct KernelPool {
    bufs: Vec<KernelBufs>,
    free: Vec<usize>,
}

impl KernelPool {
    fn new(
        device: &wgpu::Device,
        layout: &wgpu::BindGroupLayout,
        cap: usize,
    ) -> Self {
        let mut pool = KernelPool { bufs: Vec::new(), free: Vec::new() };
        for _ in 0..2 {
            pool.push_slot(device, layout, cap);
        }
        pool
    }

    fn push_slot(&mut self, device: &wgpu::Device, layout: &wgpu::BindGroupLayout, cap: usize) {
        let in_bytes = (cap * U32_PER_CAND_IN * 4) as u64;
        let out_bytes = (cap * U32_PER_CAND_OUT * 4) as u64;
        let hit_bytes = (HIT_U32 * 4) as u64;
        let in_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("candidates"),
            size: in_bytes.max(16),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let out_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("pmks"),
            size: out_bytes.max(16),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let hit_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("hits"),
            size: hit_bytes,
            usage: wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_DST
                | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let read_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("readback"),
            size: out_bytes.max(hit_bytes),
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let param_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("params"),
            size: (PARAM_U32 * 4) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("pbkdf2-bg"),
            layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: param_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 1, resource: in_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 2, resource: out_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 3, resource: hit_buf.as_entire_binding() },
            ],
        });
        self.bufs.push(KernelBufs { in_buf, out_buf, hit_buf, read_buf, param_buf, bind_group });
        self.free.push(self.bufs.len() - 1);
    }

    /// Take a free slot (index), growing the pool when the pipeline is
    /// deeper than anticipated.
    fn take(&mut self, device: &wgpu::Device, layout: &wgpu::BindGroupLayout, cap: usize) -> usize {
        match self.free.pop() {
            Some(i) => i,
            None => {
                self.push_slot(device, layout, cap);
                self.free.pop().expect("push_slot frees the new slot")
            }
        }
    }
}

/// Read-back scope of a dispatch: 16-byte hit slot (crack runs) or full
/// PMK rows (rainbow-build runs).
#[derive(Clone, Copy)]
enum Readback {
    Hits,
    Pmks(usize),
}

impl Readback {
    fn bytes(self) -> usize {
        match self {
            Readback::Hits => HIT_U32 * 4,
            Readback::Pmks(n) => n * U32_PER_CAND_OUT * 4,
        }
    }
}

pub struct GpuCracker {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    pmk_pipeline: wgpu::ComputePipeline,
    layout: wgpu::BindGroupLayout,
    name: String,
    batch: u32,
    /// Persistent dispatch buffers, two slots — the pipeline keeps at most
    /// two kernels in flight (current + next); creating buffers per batch
    /// was the dominant host-side churn. Interior mutability: `crack`
    /// borrows `&self`.
    pool: std::cell::RefCell<Option<KernelPool>>,
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
        // Need storage buffers of BATCH × 64 B in and BATCH × 40 B out.
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

        let shader_desc = wgpu::ShaderModuleDescriptor {
            label: Some("pbkdf2.wgsl"),
            source: wgpu::ShaderSource::Wgsl(include_str!("pbkdf2.wgsl").into()),
        };
        // The module carries no user input; skip naga's runtime bounds
        // checks (a tail-item guard in WGSL already clamps the last
        // partial batch). SAFETY: module is a static, trusted WGSL source.
        let shader = unsafe {
            device
                .create_shader_module_trusted(shader_desc, wgpu::ShaderRuntimeChecks::unchecked())
        };

        let storage_entry = |binding: u32, read_only: bool| wgpu::BindGroupLayoutEntry {
            binding,
            visibility: wgpu::ShaderStages::COMPUTE,
            ty: wgpu::BindingType::Buffer {
                ty: wgpu::BufferBindingType::Storage { read_only },
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        };
        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("pbkdf2-layout"),
            entries: &[
                storage_entry(0, true),  // params
                storage_entry(1, true),  // candidates
                storage_entry(2, false), // outputs
                storage_entry(3, false), // hits
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("pbkdf2-pipeline-layout"),
            bind_group_layouts: &[Some(&layout)],
            immediate_size: 0,
        });

        let make_pipeline = |label, entry| {
            device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some(label),
                layout: Some(&pipeline_layout),
                module: &shader,
                entry_point: Some(entry),
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                cache: None,
            })
        };
        let pipeline = make_pipeline("pbkdf2-crack-pipeline", "main");
        let pmk_pipeline = make_pipeline("pbkdf2-pmk-pipeline", "pmk_out");

        Some(GpuCracker {
            device,
            queue,
            pipeline,
            pmk_pipeline,
            layout,
            name: format!("{} ({:?})", info.name, info.backend),
            batch: BATCH,
            pool: std::cell::RefCell::new(None),
        })
    }

    pub fn device_name(&self) -> String {
        self.name.clone()
    }

    /// Dispatch WITHOUT waiting: returns an in-flight handle so next-batch
    /// packing overlaps the GPU. `params` is 140 u32 (see [`GpuTargetCtx`]);
    /// `pipeline` picks main vs pmk_out. None for empty input.
    fn submit_kernel(
        &self,
        inputs: &[u32],
        params: &[u32],
        readback: Readback,
        pmk_pipeline: bool,
    ) -> Option<PendingKernel> {
        let n = inputs.len() / U32_PER_CAND_IN;
        if n == 0 {
            return None;
        }
        debug_assert!(n <= self.batch as usize, "kernel buffers sized for one batch");
        debug_assert_eq!(params.len(), PARAM_U32);

        let slot = {
            let mut pool = self.pool.borrow_mut();
            let pool = pool.get_or_insert_with(|| {
                KernelPool::new(&self.device, &self.layout, self.batch as usize)
            });
            pool.take(&self.device, &self.layout, self.batch as usize)
        };
        let (in_buf, out_buf, hit_buf, read_buf, param_buf, bind_group) = {
            let pool = self.pool.borrow();
            let bufs = &pool.as_ref().expect("pool just created").bufs[slot];
            (
                bufs.in_buf.clone(),
                bufs.out_buf.clone(),
                bufs.hit_buf.clone(),
                bufs.read_buf.clone(),
                bufs.param_buf.clone(),
                bufs.bind_group.clone(),
            )
        };

        self.queue.write_buffer(&param_buf, 0, u32s_as_bytes(params));
        self.queue.write_buffer(&hit_buf, 0, &[0u8; 16]);
        self.queue.write_buffer(&in_buf, 0, u32s_as_bytes(inputs));

        let read_u32 = readback.bytes() / 4;
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
            pass.set_pipeline(if pmk_pipeline { &self.pmk_pipeline } else { &self.pipeline });
            pass.set_bind_group(0, &bind_group, &[]);
            // Two candidates per thread.
            pass.dispatch_workgroups(n.div_ceil(WORKGROUP_SIZE as usize) as u32, 1, 1);
        }
        match readback {
            Readback::Hits => {
                encoder.copy_buffer_to_buffer(&hit_buf, 0, &read_buf, 0, readback.bytes() as u64)
            }
            Readback::Pmks(_) => encoder.copy_buffer_to_buffer(
                &out_buf,
                0,
                &read_buf,
                0,
                readback.bytes() as u64,
            ),
        }
        let sub = self.queue.submit([encoder.finish()]);

        let (tx, rx) = std::sync::mpsc::channel();
        read_buf
            .slice(..readback.bytes() as u64)
            .map_async(wgpu::MapMode::Read, move |res| {
                let _ = tx.send(res);
            });

        Some(PendingKernel { read_buf, slot, rx, sub, read_u32 })
    }

    /// Wait on a dispatched kernel (timeout: hung/compute-heavy dispatch)
    /// and read back the requested words. None on device-lost/hang. The
    /// pool slot is freed for the next dispatch.
    fn wait_kernel(&self, pending: PendingKernel) -> Option<Vec<u32>> {
        let PendingKernel { read_buf, slot, rx, sub, read_u32 } = pending;
        // Any exit path returns the slot; a wedged slot must not deadlock
        // a later run.
        let _guard = SlotGuard { pool: &self.pool, slot };

        let mut waited = Duration::ZERO;
        let step = Duration::from_millis(8);
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

        let bytes = read_u32 * 4;
        let view = read_buf.slice(..bytes as u64).get_mapped_range().ok()?;
        let mut out = Vec::with_capacity(read_u32);
        for chunk in view[..bytes].chunks_exact(4) {
            out.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        drop(view);
        read_buf.unmap();
        Some(out)
    }

    /// Compute PMKs for a word batch (rainbow-table build; `pmk_out`
    /// pipeline). Halves the batch size once on device-lost/timeout; on a
    /// repeated failure returns None.
    pub(crate) fn pmk_batch_gpu(&self, words: &[Vec<u8>], salt: &[u8]) -> Option<Vec<[u8; 32]>> {
        if salt.len() > 51 {
            return None;
        }
        let mut params = vec![0u32; PARAM_U32];
        params[0] = ITERATIONS << 1;
        let u1 = u_msg(salt, 1);
        let u2 = u_msg(salt, 2);
        params[P_HEADER..P_HEADER + 16].copy_from_slice(&u1);
        params[P_HEADER + 16..P_HEADER + 32].copy_from_slice(&u2);

        let mut cur: Vec<Vec<u8>> = words.to_vec();
        let mut attempts = 0u8;
        loop {
            params[4] = cur.len() as u32;
            let inputs = pack_candidates(&cur);
            let sub =
                self.submit_kernel(&inputs, &params, Readback::Pmks(cur.len()), true)?;
            if let Some(out) = self.wait_kernel(sub) {
                let mut pmks = Vec::with_capacity(cur.len());
                for row in out.chunks_exact(U32_PER_CAND_OUT) {
                    let mut pmk = [0u8; 32];
                    for (i, w) in row[..8].iter().enumerate() {
                        pmk[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
                    }
                    pmks.push(pmk);
                }
                return Some(pmks);
            }
            attempts += 1;
            if attempts > 1 || cur.len() == 1 {
                return None;
            }
            let half = cur.len().div_ceil(2);
            cur = cur[..half].to_vec();
        }
    }

    /// Stream `words` through the GPU, calling `progress(done, hps)` per
    /// finished batch. Honors `stop` between batches. Returns the
    /// passphrase on an on-device MIC/PMKID match (hit-slot readback).
    ///
    /// The kernel verifies candidates itself: per batch the host packs
    /// raw bytes (memcpy-rate), uploads 64B/candidate and read back a
    /// 16-byte hit slot — the previous midstate/upload + CPU-MIC phases
    /// were the throughput bottleneck, not the chain.
    pub fn crack(
        &self,
        target: &CrackTarget,
        words: &mut dyn Iterator<Item = Vec<u8>>,
        progress: &mut dyn FnMut(u64, f64),
        stop: &Arc<AtomicBool>,
    ) -> Option<String> {
        let ctx = gpu_ctx(target)?;
        let mut done = 0u64;
        let started = Instant::now();
        let batch_cap = self.batch as usize;

        fn collect(words: &mut dyn Iterator<Item = Vec<u8>>, cap: usize) -> Vec<Vec<u8>> {
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(cap);
            while batch.len() < cap {
                match words.next() {
                    Some(w) => batch.push(w),
                    None => break,
                }
            }
            batch
        }
        let tick = |done: u64, started: Instant, progress: &mut dyn FnMut(u64, f64)| {
            let secs = started.elapsed().as_secs_f64().max(1e-6);
            progress(done, done as f64 / secs);
        };
        // Drain an aborted pipeline slot: never drop a mapped-read buffer
        // without polling it through.
        let drain = |pending: Option<PendingKernel>| {
            if let Some(p) = pending {
                let _ = self.wait_kernel(p);
            }
        };

        let mut cur_words = collect(words, batch_cap);
        if cur_words.is_empty() {
            return None;
        }
        let mut pending = Some(self.submit_kernel(
            &pack_candidates(&cur_words),
            &ctx.params_words(cur_words.len() as u32),
            Readback::Hits,
            false,
        )?);

        loop {
            if stop.load(Ordering::Relaxed) {
                drain(pending.take());
                return None;
            }
            // While the GPU verifies batch N on-device: fetch + pack the
            // next batch and hand it to the GPU as soon as possible.
            let next_words = collect(words, batch_cap);
            let next_pending = if next_words.is_empty() {
                None
            } else {
                Some(self.submit_kernel(
                    &pack_candidates(&next_words),
                    &ctx.params_words(next_words.len() as u32),
                    Readback::Hits,
                    false,
                )?)
            };

            let cur_pending = pending.take().expect("pipeline: one batch in flight");
            let Some(hit) = self.wait_kernel(cur_pending) else {
                drain(next_pending);
                return None;
            };
            // A hit slot write is dispatched-and-completed before the map
            // resolves: flag==1 with gid valid.
            if hit[0] != 0 {
                drain(next_pending);
                let gid = hit[1] as usize;
                done += gid as u64 + 1;
                tick(done, started, progress);
                return cur_words.get(gid).and_then(|w| String::from_utf8(w.clone()).ok());
            }
            done += cur_words.len() as u64;
            tick(done, started, progress);

            let Some(next_pending) = next_pending else {
                return None; // stream exhausted; nothing in flight
            };
            cur_words = next_words;
            pending = Some(next_pending);
        }
    }
}

/// Borrow a `&[u32]` as `&[u8]` for queue.write_buffer WITHOUT copying
/// (65536-candidate batches make the old 5 MiB memcpy per dispatch
/// measurable). Compiled only for little-endian hosts: the kernel's wire
/// format is native LE u32, matching memory layout.
#[cfg(target_endian = "little")]
fn u32s_as_bytes(v: &[u32]) -> &[u8] {
    // SAFETY: u32 has no padding and outlives the call; the kernel expects
    // exactly these bytes.
    unsafe { std::slice::from_raw_parts(v.as_ptr().cast::<u8>(), std::mem::size_of_val(v)) }
}

#[cfg(target_endian = "big")]
compile_error!("GPU cracker wire format assumes a little-endian host");

// ---------------------------------------------------------------------------
// CPU cracker (reference-fallback path)
// ---------------------------------------------------------------------------

/// Per-word PMK sink for pure-CPU cracks (per-SSID PMK cache population):
/// the caller feeds the PMK already computed for the compare, so caching
/// costs only the write. The first push error is surfaced through the log
/// callback ONCE, then the sink disables itself silently — a partially
/// written cache stays readable and useful.
pub struct CpuPmkSink {
    w: Option<rainbow::TableWriter>,
    log: Box<dyn FnMut(String) + Send>,
}

impl CpuPmkSink {
    pub fn new(w: rainbow::TableWriter, log: Box<dyn FnMut(String) + Send>) -> Self {
        CpuPmkSink { w: Some(w), log }
    }

    /// Write `(pmk, word)`; errors log once and then disable the sink.
    pub fn push(&mut self, pmk: &[u8; 32], word: &[u8]) {
        if let Some(w) = &mut self.w {
            if let Err(e) = w.push(pmk, word) {
                (self.log)(format!("pmk cache: write failed ({e}) — cache left partial"));
                self.w = None;
            }
        }
    }

    /// Flush the writer; number of entries appended by THIS sink.
    pub fn finish(self) -> std::io::Result<u64> {
        match self.w {
            Some(w) => w.finish(),
            None => Ok(0),
        }
    }
}

/// Streaming CPU cracker with the same contract as `GpuCracker::crack`.
/// `cache_sink`, when given, receives `(pmk, word)` for every tried
/// candidate (PMK cache population: pure-CPU runs only, caller's policy).
pub fn cpu_crack(
    target: &CrackTarget,
    words: &mut dyn Iterator<Item = Vec<u8>>,
    progress: &mut dyn FnMut(u64, f64),
    stop: &Arc<AtomicBool>,
    cache_sink: Option<&mut CpuPmkSink>,
) -> Option<String> {
    if matches!(target, CrackTarget::Handshake(h) if h.eapol_m2.len() < 99) {
        return None;
    }
    let salt = target.essid().as_bytes();
    let prepared = prepare_target(target);
    let mut sink = cache_sink;
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
            if let Some(s) = sink.as_deref_mut() {
                s.push(&key, w);
            }
            if prepared_matches(&prepared, &key) {
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

    pub(crate) fn synthetic_target(ssid: &str, pass: &[u8], key_ver: u8) -> CrackTarget {
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

    pub(crate) fn synthetic_pmkid(ssid: &str, pass: &[u8]) -> CrackTarget {
        let ap = "aa:bb:cc:dd:ee:ff".parse::<MacAddr>().unwrap();
        let sta = "11:22:33:44:55:66".parse::<MacAddr>().unwrap();
        let key = crypto::pmk(pass, ssid.as_bytes());
        CrackTarget::Pmkid(crate::common::PmkidCapture {
            ap,
            client: sta,
            essid: ssid.to_string(),
            pmkid: crypto::pmkid_hash(&key, &ap, &sta),
        })
    }

    #[test]
    fn host_padded_blocks_match_reference() {
        // The host's padded HMAC message blocks must be exactly what the
        // reference sha1/hmac stack computes: HMAC(K, msg) from a given
        // midstate pair must equal feeding the padded blocks through
        // compress-free reference code. Easiest ground truth: verify()
        // covers the whole chain via crypto::verify in target tests; here
        // pin just the padding invariants (0x80 at len, bitlen tail).
        let msg = b"PMK Name012345";
        let (words, n) = padded_blocks(msg);
        assert_eq!(n, 1);
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        assert_eq!(&bytes[..msg.len()], msg);
        assert_eq!(bytes[msg.len()], 0x80);
        assert_eq!(
            u64::from_be_bytes(bytes[56..64].try_into().unwrap()),
            ((64 + msg.len()) as u64) * 8
        );
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
        let pmks = crk.pmk_batch_gpu(&words, salt).expect("kernel must complete");
        assert_eq!(pmks.len(), words.len());
        for (w, k) in words.iter().zip(pmks.iter()) {
            let mut dk = [0u8; 40];
            crypto::pbkdf2_hmac_sha1(w, salt, 4096, &mut dk);
            assert_eq!(&k[..], &dk[..32], "GPU PMK mismatch for {w:?}");
            // Also bit-exact vs the RFC-anchored crypto::pmk.
            assert_eq!(k, &crypto::pmk(w, salt), "crypto::pmk mismatch for {w:?}");
        }
    }

    #[test]
    #[ignore = "perf bench: full crack-loop effective throughput"]
    fn crack_loop_effective_hps() {
        let Some(crk) = GpuCracker::try_new() else {
            eprintln!("no GPU adapter, skipping");
            return;
        };
        let target = synthetic_target("parafin", b"sup3r-secret", 2);
        const N: usize = 65536 * 6;
        let words: Vec<Vec<u8>> = (0..N).map(|i| format!("probe{i:09}").into_bytes()).collect();
        let mut it = words.into_iter();
        let stop = Arc::new(AtomicBool::new(false));
        let t0 = Instant::now();
        let found = crk.crack(&target, &mut it, &mut |_, _| {}, &stop);
        assert!(found.is_none());
        let wall = t0.elapsed().as_secs_f64();
        eprintln!(
            "full crack loop on {}: {:.0} H/s effective ({} candidates in {:.2}s)",
            crk.device_name(),
            N as f64 / wall,
            N,
            wall
        );
        // Sanity: effective must be within 4x of kernel-only, never CPU-slow.
        assert!(N as f64 / wall > 50_000.0, "effective throughput collapsed");
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
        // crack returns at the hit batch, possibly before end-of-batch.
        assert!(last_done <= 65536, "progress reported {last_done}");
        assert!(last_hps >= 0.0);
    }

    #[test]
    fn gpu_finds_planted_pmkid() {
        let Some(crk) = GpuCracker::try_new() else {
            eprintln!("no GPU adapter, skipping");
            return;
        };
        let target = synthetic_pmkid("parafin", b"hunter2!!");
        let words: Vec<Vec<u8>> = vec![b"nope-nope".to_vec(), b"hunter2!!".to_vec()];
        let mut it = words.into_iter();
        let stop = Arc::new(AtomicBool::new(false));
        let found = crk.crack(&target, &mut it, &mut |_, _| {}, &stop);
        assert_eq!(found.as_deref(), Some("hunter2!!"));
    }

    #[test]
    fn gpu_rejects_wrong_pass_and_routes_kv3() {
        let Some(crk) = GpuCracker::try_new() else {
            eprintln!("no GPU adapter, skipping");
            return;
        };
        // Wrong candidate must NOT trip the on-device verifier.
        let target = synthetic_target("parafin", b"sup3r-secret", 2);
        let words: Vec<Vec<u8>> = (0..64).map(|i| format!("zz{:07}", i).into_bytes()).collect();
        let mut it = words.into_iter();
        let stop = Arc::new(AtomicBool::new(false));
        assert!(crk.crack(&target, &mut it, &mut |_, _| {}, &stop).is_none());
        // key_ver 3 (AES-CMAC) is not expressible in the SHA1 shader.
        let kv3 = synthetic_target("parafin", b"sup3r-secret", 3);
        assert!(!gpu_verifiable(&kv3));
        // ...and long ESSIDs (spill the one-block U message) route to CPU.
        let long = synthetic_target(&"s".repeat(52), b"sup3r-secret", 2);
        assert!(!gpu_verifiable(&long));
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
        let found = cpu_crack(&target, &mut it, &mut |_, _| {}, &stop, None);
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
        let found = cpu_crack(&target, &mut it, &mut |_, _| {}, &stop, None);
        assert_eq!(found.as_deref(), Some("hunter2!!"));
    }

    #[test]
    fn stop_flag_short_circuits() {
        let pass = b"sup3r-secret";
        let target = synthetic_target("parafin", pass, 2);
        let words: Vec<Vec<u8>> = (0..2000).map(|i| format!("zz{:07}", i).into_bytes()).collect();
        let mut it = words.into_iter();
        let stop = Arc::new(AtomicBool::new(true));
        assert!(cpu_crack(&target, &mut it, &mut |_, _| {}, &stop, None).is_none());
        if let Some(crk) = GpuCracker::try_new() {
            let words2: Vec<Vec<u8>> = (0..2000).map(|i| format!("zz{:07}", i).into_bytes()).collect();
            let mut it2 = words2.into_iter();
            assert!(crk.crack(&target, &mut it2, &mut |_, _| {}, &stop).is_none());
        }
    }
}
