import fs from 'fs';
import path from 'path';
import { WORKSPACE_FILES } from '../src/data/workspaceData';

console.log('Unpacking FerrousX Rust workspace from workspaceData.ts...');

for (const file of WORKSPACE_FILES) {
  const targetPath = path.resolve(process.cwd(), file.path);
  const targetDir = path.dirname(targetPath);
  
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }
  
  fs.writeFileSync(targetPath, file.code, 'utf-8');
  console.log(`Created: ${file.path}`);
}

// Also create crate Cargo.tomls if missing
const coreCargo = `[package]
name = "ferrousx-core"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
ferrousx-config = { path = "../ferrousx-config" }
tokio.workspace = true
tokio-uring.workspace = true
io-uring.workspace = true
socket2.workspace = true
nix.workspace = true
core_affinity.workspace = true
libc.workspace = true
bytes.workspace = true
bumpalo.workspace = true
tracing.workspace = true
`;

const httpCargo = `[package]
name = "ferrousx-http"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
ferrousx-core = { path = "../ferrousx-core" }
ferrousx-config = { path = "../ferrousx-config" }
tokio.workspace = true
rustls.workspace = true
tokio-rustls.workspace = true
rustls-pemfile.workspace = true
quinn.workspace = true
h3.workspace = true
h3-quinn.workspace = true
h2.workspace = true
httparse.workspace = true
http.workspace = true
bytes.workspace = true
bumpalo.workspace = true
tracing.workspace = true
anyhow.workspace = true
`;

const configCargo = `[package]
name = "ferrousx-config"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
toml.workspace = true
kdl.workspace = true
arc-swap.workspace = true
notify.workspace = true
nix.workspace = true
anyhow.workspace = true
`;

const proxyCargo = `[package]
name = "ferrousx-proxy"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
ferrousx-core = { path = "../ferrousx-core" }
ferrousx-config = { path = "../ferrousx-config" }
tokio.workspace = true
bytes.workspace = true
http.workspace = true
async-compression.workspace = true
ahash.workspace = true
tracing.workspace = true
anyhow.workspace = true
`;

const panelCargo = `[package]
name = "ferrousx-panel"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
ferrousx-core = { path = "../ferrousx-core" }
ferrousx-config = { path = "../ferrousx-config" }
tokio.workspace = true
serde.workspace = true
serde_json = "1.0.138"
bytes.workspace = true
tracing.workspace = true
anyhow.workspace = true
`;

const binCargo = `[package]
name = "ferrousx-bin"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[[bin]]
name = "ferrousx-bin"
path = "src/main.rs"

[[bin]]
name = "ferrousx-ctl"
path = "src/cli.rs"

[dependencies]
ferrousx-core = { path = "../ferrousx-core" }
ferrousx-http = { path = "../ferrousx-http" }
ferrousx-config = { path = "../ferrousx-config" }
ferrousx-proxy = { path = "../ferrousx-proxy" }
ferrousx-panel = { path = "../ferrousx-panel" }
tokio.workspace = true
rustls.workspace = true
quinn.workspace = true
rustls-pemfile.workspace = true
clap = { version = "4.5.31", features = ["derive"] }
serde = { workspace = true, features = ["derive"] }
serde_json = "1.0.138"
tracing.workspace = true
tracing-subscriber.workspace = true
anyhow.workspace = true
`;

fs.writeFileSync(path.resolve(process.cwd(), 'crates/ferrousx-core/Cargo.toml'), coreCargo, 'utf-8');
fs.writeFileSync(path.resolve(process.cwd(), 'crates/ferrousx-http/Cargo.toml'), httpCargo, 'utf-8');
fs.writeFileSync(path.resolve(process.cwd(), 'crates/ferrousx-config/Cargo.toml'), configCargo, 'utf-8');
fs.writeFileSync(path.resolve(process.cwd(), 'crates/ferrousx-proxy/Cargo.toml'), proxyCargo, 'utf-8');
fs.writeFileSync(path.resolve(process.cwd(), 'crates/ferrousx-panel/Cargo.toml'), panelCargo, 'utf-8');
fs.writeFileSync(path.resolve(process.cwd(), 'crates/ferrousx-bin/Cargo.toml'), binCargo, 'utf-8');

console.log('Successfully unpacked full Rust Cargo Workspace!');
