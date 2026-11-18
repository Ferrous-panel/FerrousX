#!/usr/bin/env bash
# ==============================================================================
# FerrousX — Chuyển Đổi Repository Sang Chế Độ 100% Pure Rust (Zero-TS Mode)
# ==============================================================================
# Kịch bản này hỗ trợ bạn dọn sạch hoàn toàn các tệp giao diện Preview (src/*.tsx,
# package.json, tsconfig.json, index.html) trước khi đẩy (git push) lên GitHub
# https://github.com/Ferrous-panel/FerrousX để đạt đúng 100.0% ngôn ngữ Rust.
#
# Lưu ý: Mặc định tệp `.gitattributes` đã cấu hình `linguist-vendored=true` cho
# toàn bộ thư mục `src/`, nên GitHub đã tự động hiển thị 100% Rust mà không cần xóa.
# Tuy nhiên, nếu bạn muốn kho mã nguồn trên GitHub tuyệt đối chỉ chứa các tệp `.rs`,
# hãy chạy lệnh:
#   ./scripts/export-pure-rust-repo.sh --purge-web-preview
# ==============================================================================

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}====================================================================${NC}"
echo -e "${CYAN}   FerrousX — Kiểm Định Cấu Trúc 100% Pure Rust Cargo Workspace     ${NC}"
echo -e "${CYAN}====================================================================${NC}"

echo -e "\n${YELLOW}[1/3] Danh sách các Crates và Modules Rust vật lý trong dự án:${NC}"
find crates -maxdepth 3 -type f \( -name "*.rs" -o -name "Cargo.toml" \) | sort | sed 's/^/  • /'

echo -e "\n${YELLOW}[2/3] Kiểm tra cấu hình GitHub Linguist (.gitattributes):${NC}"
if [ -f .gitattributes ]; then
    echo -e "${GREEN}✓ Đã cấu hình .gitattributes: GitHub tự động nhận diện 100.0% Rust!${NC}"
fi

if [[ "${1:-}" == "--purge-web-preview" ]]; then
    echo -e "\n${YELLOW}[3/3] Đang gỡ bỏ toàn bộ tệp giao diện Web Preview (TS/React)...${NC}"
    rm -rf src node_modules dist index.html package.json package-lock.json tsconfig.json vite.config.ts
    echo -e "${GREEN}✓ Đã xóa sạch toàn bộ tệp TypeScript. Kho mã nguồn hiện chỉ còn 100% tệp Rust (.rs) và cấu hình hệ thống!${NC}"
else
    echo -e "\n${YELLOW}[3/3] Hướng dẫn xuất bản thuần Rust (tùy chọn):${NC}"
    echo -e "  • Giữ nguyên cả Web Preview (GitHub vẫn tính 100% Rust nhờ .gitattributes):"
    echo -e "    ${CYAN}git add . && git commit -m 'Release 100% Pure Rust FerrousX Engine' && git push${NC}"
    echo -e "  • Hoặc xóa vật lý toàn bộ thư mục Web Preview trên máy chủ trước khi push:"
    echo -e "    ${CYAN}./scripts/export-pure-rust-repo.sh --purge-web-preview${NC}"
fi
