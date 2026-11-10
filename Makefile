# ==============================================================================
# FerrousX Makefile — Standard Unix Build & Install Workflow
# ==============================================================================

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc/ferrousx
SYSTEMDDIR ?= /etc/systemd/system

.PHONY: all build release clean install uninstall test fmt

all: build

build:
	@echo "==> Biên dịch FerrousX (Debug mode)..."
	cargo build

release:
	@echo "==> Biên dịch FerrousX (Release mode với CPU native optimizations)..."
	RUSTFLAGS="-C target-cpu=native" cargo build --release

test:
	@echo "==> Chạy bộ kiểm thử (Workspace tests)..."
	cargo test --workspace

fmt:
	@echo "==> Định dạng mã nguồn..."
	cargo fmt --all

install: release
	@echo "==> Cài đặt file nhị phân vào $(BINDIR)..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 target/release/ferrousx-bin $(DESTDIR)$(BINDIR)/ferrousx-bin
	@if [ -f target/release/ferrousx-ctl ]; then \
		install -m 755 target/release/ferrousx-ctl $(DESTDIR)$(BINDIR)/ferrousx-ctl; \
	else \
		ln -sf $(BINDIR)/ferrousx-bin $(DESTDIR)$(BINDIR)/ferrousx-ctl; \
	fi
	@echo "==> Cấu hình thư mục cấu hình $(SYSCONFDIR)..."
	install -d $(DESTDIR)$(SYSCONFDIR)/ssl
	install -d $(DESTDIR)/var/log/ferrousx
	install -d $(DESTDIR)/run/ferrousx
	@if [ ! -f $(DESTDIR)$(SYSCONFDIR)/ferrousx.toml ]; then \
		if [ -f conf/ferrousx.toml ]; then \
			install -m 644 conf/ferrousx.toml $(DESTDIR)$(SYSCONFDIR)/ferrousx.toml; \
		fi \
	fi
	@if [ -d /etc/systemd/system ] && [ -z "$(DESTDIR)" ]; then \
		echo "==> Cài đặt Systemd unit..."; \
		install -m 644 scripts/ferrousx.service /etc/systemd/system/ferrousx.service 2>/dev/null || true; \
		systemctl daemon-reload 2>/dev/null || true; \
	fi
	@echo "==> Cài đặt hoàn tất! Khởi động bằng: sudo systemctl start ferrousx"

uninstall:
	@echo "==> Gỡ bỏ FerrousX..."
	rm -f $(DESTDIR)$(BINDIR)/ferrousx-bin
	rm -f $(DESTDIR)$(BINDIR)/ferrousx-ctl
	rm -f $(DESTDIR)$(SYSTEMDDIR)/ferrousx.service
	@echo "==> Đã gỡ bỏ file nhị phân và service."

clean:
	@echo "==> Dọn dẹp bản build..."
	cargo clean
