# MeshLink

Secure P2P Mesh Networking Platform.

MeshLink is a desktop mesh networking system based on:

- Tauri 2
- Rust
- Go Controller
- DirectLink P2P
- Noise IK Encryption
- Wintun Overlay Network


## Features

### Completed

- DirectLink UDP P2P connection
- NAT traversal
- Noise IK encrypted transport
- Device identity system
- Controller identity registry
- Friend system
- 6 digit connection code
- Recent connection management
- Process lifecycle management


### Planned

- N2N Supernode fallback
- Automatic Path Manager
- Multi-path connection
- File transfer
- Multi-thread segmented transfer
- Resume download
- Remote desktop
- Cloudflare disaster relay


## Architecture

MeshLink UI
|
Tauri Client
|
mesh-agent
|
| Controller |
| DirectLink |
| N2N |
| Wintun Overlay |


## Development Status

Current milestone:

M1-1.5 Completed


## Project Rules

All AI developers must:

1. Update docs/ai before finishing a milestone
2. Keep CHANGELOG updated
3. Commit changes with clear messages
4. Never remove security design without approval


## License

Private development project.
