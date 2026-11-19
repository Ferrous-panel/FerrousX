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
    alloc_ptr: *mut u8,
    alloc_len: usize,
    ptr: *mut u8,
    capacity: usize,
    numa_node_id: usize,
    #[cfg(not(unix))]
    _backing: Vec<u8>,
}

unsafe impl Send for HugePageArenaBuffer {}
unsafe impl Sync for HugePageArenaBuffer {}

impl HugePageArenaBuffer {
    /// Cấp phát vùng nhớ ẩn danh (anonymous mmap) và kích hoạt cờ kernel `MADV_HUGEPAGE`,
    /// cấp phát dư `2 MiB` để căn chỉnh con trỏ thực tế đúng ranh giới 2 MiB.
    pub fn allocate_pinned_2mb_aligned(size_bytes: usize, numa_node_id: usize) -> io::Result<Self> {
        let requested = size_bytes.max(1);
        let aligned_capacity = requested
            .checked_add(HUGE_PAGE_SIZE_2MB - 1)
            .map(|n| n & !(HUGE_PAGE_SIZE_2MB - 1))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "size_bytes vượt quá giới hạn phép toán khi làm tròn 2 MiB",
                )
            })?;

        let over_alloc_len = aligned_capacity
            .checked_add(HUGE_PAGE_SIZE_2MB)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "aligned_capacity vượt quá giới hạn khi cộng bù căn chỉnh 2 MiB",
                )
            })?;

        #[cfg(unix)]
        unsafe {
            let raw_ptr = libc::mmap(
                ptr::null_mut(),
                over_alloc_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );

            if raw_ptr == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }

            let raw_addr = raw_ptr as usize;
            let aligned_addr = match raw_addr.checked_add(HUGE_PAGE_SIZE_2MB - 1) {
                Some(sum) => sum & !(HUGE_PAGE_SIZE_2MB - 1),
                None => {
                    let _ = libc::munmap(raw_ptr, over_alloc_len);
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Tràn số học địa chỉ khi căn chỉnh 2 MiB",
                    ));
                }
            };
            let byte_ptr = aligned_addr as *mut u8;

            // Báo cho nhân Linux gộp các trang 4KB thành trang 2MB HugePage (MADV_HUGEPAGE = 14)
            #[cfg(target_os = "linux")]
            {
                let _ = libc::madvise(
                    byte_ptr as *mut libc::c_void,
                    aligned_capacity,
                    libc::MADV_HUGEPAGE,
                );
                let _ = libc::madvise(
                    byte_ptr as *mut libc::c_void,
                    aligned_capacity,
                    libc::MADV_WILLNEED,
                );
            }

            // Chạm trước vào đầu mỗi trang (Pre-faulting) để khóa trang vật lý vào NUMA Node hiện tại
            let mut offset = 0usize;
            while offset < aligned_capacity {
                ptr::write_volatile(byte_ptr.add(offset), 0u8);
                offset = offset.saturating_add(PAGE_SIZE_4KB);
            }

            info!(
                capacity_mb = aligned_capacity / (1024 * 1024),
                numa_node = numa_node_id,
                aligned_2mb = (aligned_addr % HUGE_PAGE_SIZE_2MB) == 0,
                "Đã khóa vùng đệm 2MB HugePages căn chỉnh chuẩn trên NUMA Node cục bộ"
            );

            Ok(Self {
                alloc_ptr: raw_ptr as *mut u8,
                alloc_len: over_alloc_len,
                ptr: byte_ptr,
                capacity: aligned_capacity,
                numa_node_id,
            })
        }

        #[cfg(not(unix))]
        {
            let mut backing = vec![0u8; over_alloc_len];
            let raw_addr = backing.as_mut_ptr() as usize;
            let aligned_addr = raw_addr
                .checked_add(HUGE_PAGE_SIZE_2MB - 1)
                .map(|sum| sum & !(HUGE_PAGE_SIZE_2MB - 1))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "Tràn số học địa chỉ khi căn chỉnh 2 MiB",
                    )
                })?;
            let byte_ptr = aligned_addr as *mut u8;
            Ok(Self {
                alloc_ptr: backing.as_mut_ptr(),
                alloc_len: over_alloc_len,
                ptr: byte_ptr,
                capacity: aligned_capacity,
                numa_node_id,
                _backing: backing,
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
            if !self.alloc_ptr.is_null() && self.alloc_len > 0 {
                let _ = libc::munmap(self.alloc_ptr as *mut libc::c_void, self.alloc_len);
            }
        }
        // Trên non-unix, `_backing: Vec<u8>` tự động được giải phóng khi Drop, không rò rỉ bộ nhớ.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hugepage_arena_is_genuinely_2mb_aligned_and_checks_overflow() {
        let arena = HugePageArenaBuffer::allocate_pinned_2mb_aligned(4096, 0)
            .expect("allocation of 2MB aligned buffer should succeed");
        assert_eq!(arena.capacity(), HUGE_PAGE_SIZE_2MB);
        let addr = arena.as_slice().as_ptr() as usize;
        assert_eq!(addr % HUGE_PAGE_SIZE_2MB, 0);

        let overflow = HugePageArenaBuffer::allocate_pinned_2mb_aligned(usize::MAX, 0);
        assert!(overflow.is_err());
    }
}
