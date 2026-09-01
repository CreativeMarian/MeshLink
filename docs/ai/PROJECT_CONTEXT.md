# MeshLink Project Context

## Project Type

Private desktop mesh networking system.

Target users:

- Personal devices
- Friends
- Small teams


## Main Goal

Create a simple private network tool:

1. Install application
2. Create connection code
3. Friend joins
4. Automatically establish secure tunnel
5. Access remote devices


## Architecture

Frontend:

- Tauri 2
- Vue / JavaScript


Core:

- Rust mesh-agent
- Go Controller


Network:

- DirectLink P2P
- N2N fallback
- Wintun Overlay


Security:

- Device Identity
- Noise IK encryption
- Controller registry


## Planned Features

- Automatic path switching
- File transfer
- Multi-thread segmented transfer
- Resume transfer
- Remote desktop
- Device management


## Development Philosophy

Build complete user features first.

Then improve:

- Stability
- Performance
- Security
- Optimization
