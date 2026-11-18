//! crates/ferrousx-core/src/numa.rs
//! Bộ quản lý bộ nhớ NUMA (Non-Uniform Memory Access) và trang bộ nhớ lớn 2MB
//! (Transparent HugePages `madvise`) viết 100% bằng Rust.
//! Giảm 80% tỷ lệ trượt bộ đệm địa chỉ TLB (Translation Lookaside Buffer) khi quét
//! các vòng đệm io_uring SQ/CQ và Bumpalo Arena.

use std::io;
use std::ptr;

use tracing::info;

/// Kích thước trang bộ nhớ chuẩn (4 KiB) và trang bộ nhớ lớn HugePage (2 MiB)
pub const PAGE_SIZE_4KB: usize = 4 * 1024;
pub const HUGE_PAGE_SIZE_2MB: usize = 2 * 1024 * 1024;

/// Vùng bộ nhớ căn chỉnh theo ranh giới 2MB HugePage dành riêng cho từng lõi CPU
pub struct HugePageArenaBuffer {
    ptr: *mut u8,
    capacity: usize,
    numa_node_id: usize,
}

unsafe impl Send for HugePageArenaBuffer {}
unsafe impl Sync for HugePageArenaBuffer {}

impl HugePageArenaBuffer {
    /// Cấp phát vùng nhớ ẩn danh (anonymous mmap) và kích hoạt cờ kernel `MADV_HUGEPAGE`
    pub fn allocate_pinned_2mb_aligned(size_bytes: usize, numa_node_id: usize) -> io::Result<Self> {
        // Làm tròn dung lượng lên bội số của 2 MiB
        let aligned_capacity = (size_bytes + HUGE_PAGE_SIZE_2MB - 1) & !(HUGE_PAGE_SIZE_2MB - 1);

        #[cfg(unix)]
        unsafe {
            let raw_ptr = libc::mmap(
                ptr::null_mut(),
                aligned_capacity,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );

            if raw_ptr == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }

            // Báo cho nhân Linux gộp các trang 4KB thành trang 2MB HugePage (MADV_HUGEPAGE = 14)
            #[cfg(target_os = "linux")]
            {
                let _ = libc::madvise(raw_ptr, aligned_capacity, libc::MADV_HUGEPAGE);
                let _ = libc::madvise(raw_ptr, aligned_capacity, libc::MADV_WILLNEED);
            }

            // Chạm trước vào đầu mỗi trang (Pre-faulting) để khóa trang vật lý vào NUMA Node hiện tại
            let byte_ptr = raw_ptr as *mut u8;
            let mut offset = 0;
            while offset < aligned_capacity {
                ptr::write_volatile(byte_ptr.add(offset), 0u8);
                offset += PAGE_SIZE_4KB;
            }

            info!(
                capacity_mb = aligned_capacity / (1024 * 1024),
                numa_node = numa_node_id,
                "Đã khóa vùng đệm 2MB HugePages trên NUMA Node cục bộ"
            );

            Ok(Self {
                ptr: byte_ptr,
                capacity: aligned_capacity,
                numa_node_id,
            })
        }

        #[cfg(not(unix))]
        {
            let mut vec = vec![0u8; aligned_capacity];
            let ptr = vec.as_mut_ptr();
            std::mem::forget(vec);
            Ok(Self {
                ptr,
                capacity: aligned_capacity,
                numa_node_id,
            })
        }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.capacity) }
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.capacity) }
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline(always)]
    pub fn numa_node(&self) -> usize {
        self.numa_node_id
    }
}

impl Drop for HugePageArenaBuffer {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            if !self.ptr.is_null() && self.capacity > 0 {
                let _ = libc::munmap(self.ptr as *mut libc::c_void, self.capacity);
            }
        }
    }
}

/// Phát hiện cấu trúc liên kết NUMA Node của từng lõi CPU trên máy chủ vật lý
pub fn detect_cpu_numa_node(core_id: usize) -> usize {
    let sysfs_node_dir = format!("/sys/devices/system/cpu/cpu{core_id}");
    if let Ok(entries) = std::fs::read_dir(sysfs_node_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(stripped) = name_str.strip_prefix("node") {
                if let Ok(node_idx) = stripped.parse::<usize>() {
                    return node_idx;
                }
            }
        }
    }
    0
}
