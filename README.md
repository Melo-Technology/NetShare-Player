<div align="center">
  <img src="assets/logo.svg" width="100" height="100" alt="NetShare Logo">

# NETSHARE PLAYER
### Your files. Your network. Your terms.

[![License: Freeware](https://img.shields.io/badge/License-Freeware-white.svg?style=flat-square)](https://github.com/melotechnology/netshare-player)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Android-white?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.1.0-white?style=flat-square)
![Status](https://img.shields.io/badge/Status-Ultra--Fast-white?style=flat-square)

**Stream any file from your computer to your phone — instantly. No cloud. No accounts. No limits.**  
Local network, or anywhere in the world via secure tunnel.

---

</div>

## The Concept

**NetShare Player** turns your computer into a private media hub. No upload, no subscription, no third-party server. Your files travel directly from your PC to your phone — over your own Wi-Fi, or through an encrypted tunnel when you're away from home.

Built for those who value privacy, speed, and a clean minimalist aesthetic.

- **Private by Design** — Your data never touches any cloud server.
- **Zero Configuration** — Auto-discovery finds your PC automatically.
- **No Internet Required** — Works entirely on your local network.
- **Global Access** — One click to share publicly via SSH tunnel.

---

## How It Works

1. **Select & Start** — Run NetShare Server and pick any folder on your PC.
2. **Pair** — Scan the QR code with the mobile app, or let auto-discovery find your PC.
3. **Stream** — Your files appear instantly on your phone.

---

## The Experience

### Desktop Launcher (Windows)

A sleek, geometric Python application that serves as your gateway.

- **One-Scan Connection** — QR code generation for instant mobile pairing.
- **Smart Indexing** — High-speed file walking with Gzip caching — restarts in seconds.
- **Live Watchdog** — Automatically detects when you add or delete files.
- **Local Password** — Optional password to restrict LAN access.
- **Keep Awake** — Prevents your PC from sleeping while serving files.
- **Dark / Light Mode** — Toggle between themes.

### Public Sharing via SSH Tunnel

Share your files with anyone on the internet — not just your local network.

- **One-Click** — Hit SHARE PUBLICLY to get a public HTTPS URL instantly.
- **No Account Required** — Powered by [localhost.run](https://localhost.run).
- **Dual Password System** — Tunnel clients and LAN clients use independent passwords.
- **Auto-Reconnect** — The tunnel reconnects automatically with exponential backoff if the connection drops.

### Mobile App (Android)

A fluid, high-performance Flutter application designed for seamless media consumption.

- **Auto Discovery** — Finds all NetShare servers on your Wi-Fi automatically.
- **Remote Access** — Connect from anywhere via ngrok, Tailscale, SSH tunnel, or port forwarding.
- **Cinematic Video** — Hardware-accelerated playback with gesture controls, subtitles, and orientation lock.
- **Hi-Fi Audio** — Background playback with lock-screen controls and album art.
- **File Browser** — List, Grid and Detail views with breadcrumb navigation.
- **Batch Downloads** — Long-press to select, download multiple files at once.
- **Global Reach** — Fully translated into 10 languages.

---

## Remote Access Options

| Method | Difficulty | Best For |
| :--- | :--- | :--- |
| **Private Tunnel** (localhost.run) | ⚡ Fastest | Quick sharing, built into the launcher |
| **ngrok** | Easiest | Developers, temporary access |
| **Tailscale** | Most Secure | Permanent personal VPN |
| **Port Forwarding** | Permanent | Advanced users, home server |

---

## Supported Formats

| Category | Formats |
| :--- | :--- |
| **Video** | MP4, MKV, AVI, MOV, WMV, FLV, WEBM, TS |
| **Audio** | MP3, FLAC, AAC, WAV, OGG, M4A, OPUS, WMA |
| **Images** | JPG, PNG, GIF, WEBP, BMP, SVG |
| **Text** | TXT, MD, LOG, CSV, JSON, XML, YAML |
| **Documents** | PDF, DOCX, XLSX, PPTX (via native app) |

---

## Installation

### Server (PC)
Download `NetShare.Server.exe` from the [latest release](https://github.com/melotechnology/netshare-player/releases) and run it. No installation required.

### Mobile App (Android)
Download `NetShare-Player.apk` from the [latest release](https://github.com/melotechnology/netshare-player/releases) and install it on your Android device.

> **Note:** You may need to enable *Install from unknown sources* in your Android settings.

---

## Requirements

- **PC:** Windows 10 or later
- **Mobile:** Android 6.0 or later
- **Network:** Both devices on the same Wi-Fi (for local use)

---

<div align="center">

### Join the local revolution.
*Stop uploading. Start sharing.*

<br/>

**Made with ♥ by Mélo Technology**

[hello@melo.technology](mailto:hello@melo.technology) · [GitHub](https://github.com/melotechnology)

</div>
