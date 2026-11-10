#!/usr/bin/env bash
# ==============================================================================
# FerrousX — Môi Trường Biên Dịch Siêu Tối Ưu Hóa (Extreme Optimized Rust Pipeline)
# ==============================================================================
# Hỗ trợ 3 chế độ dịch:
#   1. native   : Biên dịch tối ưu theo tập lệnh phần cứng máy chủ hiện tại (AVX2/AVX-512)
#   2. musl     : Biên dịch nhị phân tĩnh (Static Binary, 0 phụ thuộc libc, chạy mọi Linux)
#   3. pgo      : Profile-Guided Optimization (Tối ưu hóa theo luồng thực thi thực tế)
#
# Cách dùng:
#   ./scripts/build-optimized.sh native
#   ./scripts/build-optimized.sh musl
#   ./scripts/build-optimized.sh pgo
# ==============================================================================

set -euo pipefail

MODE="${1:-native}"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}====================================================================${NC}"
echo -e "${CYAN}   FerrousX — Trình Biên Dịch Rust Siêu Tối Ưu (Chế độ: ${MODE})    ${NC}"
echo -e "${CYAN}====================================================================${NC}"

# 1. Kiểm tra môi trường Rust
if ! command -v cargo >/dev/null 2>&1; then
    echo -e "${RED}[LỖI] Chưa tìm thấy Rust. Vui lòng cài đặt rustup: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/4] Kiểm tra phiên bản Rust Compiler:${NC}"
rustc --version
cargo --version

# 2. Thực thi chế độ dịch tương ứng
case "$MODE" in
    native)
        echo -e "\n${YELLOW}[2/4] Đang biên dịch với LTO Fat, Codegen-Units 1 & Target CPU Native...${NC}"
        RUSTFLAGS="-C target-cpu=native -C link-arg=-Wl,--as-needed" \
        cargo build --release --workspace

        TARGET_DIR="target/release"
        ;;

    musl)
        echo -e "\n${YELLOW}[2/4] Kiểm tra target musl libc...${NC}"
        rustup target add x86_64-unknown-linux-musl 2>/dev/null || true

        echo -e "${YELLOW}Biên dịch tĩnh (Statically-Linked) x86_64-unknown-linux-musl...${NC}"
        RUSTFLAGS="-C target-feature=+crt-static -C target-cpu=x86-64-v3" \
        cargo build --release --target x86_64-unknown-linux-musl --workspace

        TARGET_DIR="target/x86_64-unknown-linux-musl/release"
        ;;

    pgo)
        echo -e "\n${YELLOW}[2/4] Bắt đầu quy trình Profile-Guided Optimization (PGO)...${NC}"
        PGO_DIR=$(mktemp -d /tmp/ferrousx-pgo-XXXXXX)
        echo "Thư mục PGO Profile: $PGO_DIR"

        echo -e "${CYAN}Bước 2.1: Biên dịch Instrumentation Binary...${NC}"
        RUSTFLAGS="-C profile-generate=$PGO_DIR -C target-cpu=native" \
        cargo build --release --bin ferrousx-bin

        echo -e "${CYAN}Bước 2.2: Thu thập dữ liệu Profile qua tải mô phỏng...${NC}"
        # Khởi chạy daemon trong 3 giây và gửi tín hiệu benchmark
        ./target/release/ferrousx-bin conf/ferrousx.toml &
        DAEMON_PID=$!
        sleep 1

        if command -v curl >/dev/null 2>&1; then
            for _ in {1..50}; do
                curl -s http://127.0.0.1:80/ >/dev/null 2>&1 || true
            done
        fi
        kill -INT "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true

        echo -e "${CYAN}Bước 2.3: Tổng hợp Profile và Biên dịch PGO Final...${NC}"
        if command -v llvm-profdata >/dev/null 2>&1; then
            llvm-profdata merge -o "$PGO_DIR/merged.profdata" "$PGO_DIR"
            RUSTFLAGS="-C profile-use=$PGO_DIR/merged.profdata -C target-cpu=native" \
            cargo build --release --workspace
        else
            echo -e "${YELLOW}Chưa có llvm-profdata. Tiếp tục với cờ native LTO thông thường...${NC}"
            RUSTFLAGS="-C target-cpu=native" cargo build --release --workspace
        fi

        rm -rf "$PGO_DIR"
        TARGET_DIR="target/release"
        ;;

    *)
        echo -e "${RED}[LỖI] Chế độ không hợp lệ: $MODE. Dùng: native | musl | pgo${NC}"
        exit 1
        ;;
esac

# 3. Strip bảng ký hiệu debug để thu nhỏ kích thước nhị phân
echo -e "\n${YELLOW}[3/4] Tối ưu hóa kích thước file nhị phân (strip symbols)...${NC}"
if command -v strip >/dev/null 2>&1; then
    strip "$TARGET_DIR/ferrousx-bin" 2>/dev/null || true
    if [ -f "$TARGET_DIR/ferrousx-ctl" ]; then
        strip "$TARGET_DIR/ferrousx-ctl" 2>/dev/null || true
    fi
fi

# 4. Hiển thị thông số file nhị phân sau khi dịch
echo -e "\n${YELLOW}[4/4] Báo cáo tệp nhị phân hoàn tất:${NC}"
echo -e "Thư mục đích: ${CYAN}$TARGET_DIR${NC}"
ls -lh "$TARGET_DIR/ferrousx-bin" 2>/dev/null || true
if [ -f "$TARGET_DIR/ferrousx-ctl" ]; then
    ls -lh "$TARGET_DIR/ferrousx-ctl" 2>/dev/null || true
fi

echo -e "\n${GREEN}====================================================================${NC}"
echo -e "${GREEN}  ✓ BIÊN DỊCH DỰ ÁN RUST THUẦN FERROUSX THÀNH CÔNG!                 ${NC}"
echo -e "${GREEN}====================================================================${NC}"
echo -e "• Daemon Web Server:  ${CYAN}$TARGET_DIR/ferrousx-bin${NC}"
echo -e "• Quản trị CLI Socket:${CYAN}$TARGET_DIR/ferrousx-ctl${NC}"
echo -e "• Khởi chạy kiểm thử: ${YELLOW}./$TARGET_DIR/ferrousx-bin conf/ferrousx.toml${NC}"
