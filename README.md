<div align="center">
  <img src="assets/logo.svg" width="100" height="100" alt="NetShare Player logo">

# NETSHARE PLAYER

### Your files. Your network. Your terms.

[![License: Freeware](https://img.shields.io/badge/License-Freeware-white.svg?style=flat-square)](https://github.com/Melo-Technology/NetShare-Player)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Android%20%7C%20Linux%20%7C%20macOS-white?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.2.5-white?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)

**Browse, stream, and download files from your computer to your phone.**  
Use your local network at home or a secure tunnel when you are away.

---

</div>

## Overview

**NetShare Player** turns your Windows computer into a private media and file-sharing hub.

Choose a folder in NetShare Server, connect with the Android app, and access your files without uploading your library to a NetShare-operated storage service or creating an account.

Your files are transferred directly between NetShare Player and the server or tunnel you configure. Optional integrations, such as Google Drive, Dropbox, Mega, or public tunnels, are only used when you explicitly enable them.

NetShare is designed for users who value privacy, performance, and control.

- **Private by Design** — Your local files remain under your control.
- **No Account Required** — Local sharing works without a NetShare account.
- **Automatic Discovery** — Find nearby servers on your Wi-Fi.
- **Offline-Friendly** — Local access does not require an internet connection.
- **Remote Access** — Connect through a supported public or private tunnel.
- **Media-First Experience** — Stream audio, video, images, and text files.
- **Multilingual** — Available in 10 languages.

---

## How It Works

1. **Select a Folder** — Start NetShare Server and choose the folder you want to share.
2. **Connect Your Device** — Use automatic discovery, enter the address manually, or scan the QR code.
3. **Browse and Stream** — Your shared files appear in NetShare Player.
4. **Download When Needed** — Save individual files or batches for offline access.

---

## NetShare Server for Windows

NetShare Server is the desktop application that makes your files available to NetShare Player.

### Fast File Indexing

- High-speed scanning of large folder collections.
- Cached file index for faster restarts.
- Automatic detection of added, removed, or renamed files.
- Background media analysis without blocking the initial scan.
- Adaptive Eco or Standard processing profile based on available CPU cores.
- Search across indexed folders and files.

### Smart Audio Analysis

NetShare Server can progressively analyze supported audio files using FFmpeg.

- Generates waveform data for the mobile player.
- Detects approximate BPM.
- Measures loudness and provides volume-normalization information.
- Detects useful ending points for smoother transitions.
- Suggests an appropriate crossfade duration for each track.
- Uses optimized analysis for very long recordings.

### Access Control

- Optional password for local-network connections.
- Independent password for public or tunnel connections.
- Configurable password-change reminders.
- Trusted-device registration.
- Temporary write authorization for protected operations.
- Premium folders protected by single-use access codes.
- Ability to revoke access codes and trusted devices.

### Smart Sharing

- Remembers recently shared folders.
- Recommends folders based on sharing frequency and recency.
- Creates a hidden reception folder for incoming uploads.
- Automatically excludes hidden reception folders from browsing and search results.

### Network Awareness

- Detects changes to the computer’s local IP address.
- Updates the displayed server address without a full restart.
- Notifies connected devices when the address changes.
- Supports local addresses, custom ports, hostnames, and HTTPS endpoints.
- Keeps the computer awake while the server is active.

### Appearance

- Dark and light themes.
- Compact server controls.
- Live connection and activity logs.
- QR code generation for quick pairing.
- Clear status indicators for local, remote, and cloud services.

---

## Remote Access and Public Sharing

NetShare Player can connect to your computer outside your local network when you configure a remote-access method.

### Built-in Quick Sharing

- Generate a temporary public HTTPS address through `localhost.run`.
- Separate local and public passwords.
- Automatic tunnel reconnection with exponential backoff.
- No additional NetShare account required.

### Custom Cloudflare Tunnel

- Connect a custom domain to NetShare Server.
- Use an HTTPS address such as `https://share.example.com`.
- Keep your home IP private behind an outbound tunnel.
- Reuse the same address instead of generating a temporary URL.

### Other Compatible Options

- Tailscale
- ngrok
- SSH tunnels
- Reverse proxies
- Port forwarding with HTTPS and appropriate security controls

> Remote streaming performance depends on the upload speed of the server’s internet connection, the tunnel provider, and the receiving device’s connection.

---

## Optional Cloud Sources

NetShare Server can expose supported cloud-storage accounts as folders inside NetShare Player.

### Supported Integrations

- Google Drive
- Dropbox
- Mega

Cloud accounts are connected on the computer running NetShare Server. The mobile app then browses the selected cloud content through the server.

> Cloud integrations are optional. Their respective providers may process traffic and account information according to their own privacy policies.

---

## NetShare Player for Android

NetShare Player is a Flutter application designed for fast browsing and media playback.

### Connection

- Automatic discovery of nearby NetShare servers.
- Manual connection using an IP address, hostname, URL, or custom port.
- QR code scanning.
- Saved-server management.
- Swipe to remove a saved server.
- Support for local and remote connections.
- Secure storage for remembered server credentials through Android Keystore.

### File Browser

- List, grid, and detail layouts.
- Breadcrumb navigation.
- Search across the connected server.
- File and folder metadata.
- Multi-selection.
- Batch downloads.
- Long-press shortcuts for downloading.
- Upload and editing actions when the server grants write permission.
- Clear read-only states when editing is unavailable.

### Audio Player

- Background playback.
- Lock-screen and notification controls.
- Album artwork and metadata.
- Interactive progress bar.
- Server-generated waveform display.
- Playback-speed control.
- Queue and playlist management.
- Audio-output selector.
- Equalizer controls.
- Loudness adjustment.
- Swipe left or right to change tracks.
- Resume playback from a previously saved position.

### Smart Crossfade

NetShare Player uses two coordinated audio decks to create smooth transitions.

- Preloads the next track before the current track ends.
- Uses equal-power volume curves for more natural transitions.
- Supports a configurable crossfade duration.
- Can disable crossfade completely.
- Uses server recommendations when adaptive crossfade is enabled.
- Falls back to normal sequential playback when a transition is unavailable.
- Handles short tracks and playlist boundaries safely.

### Video Player

- Hardware-accelerated playback when supported.
- Automatic software-decoding fallback when hardware decoding fails.
- Reliable remote streaming with authenticated range requests.
- Brightness and volume gestures.
- Double-tap and seek controls.
- Playback-speed selection.
- Audio-track and subtitle selection when available.
- Orientation handling.
- Screen-gesture lock to prevent accidental touches while watching.
- Playlist navigation.
- Resume from a saved position.

### Image Viewer

- Zoom and pan.
- Swipe between images.
- Share and download actions.
- Temporary shared files are removed from the cache after use.

### Text Viewer

- Text-file viewing.
- Editing when the connected server allows write access.
- Automatic saving.
- Clear, non-interactive read-only indicators.

### Media History

- History of recently opened audio, video, and image files.
- Filters by media type.
- Reopen available files from the original server.
- Multi-selection and deletion.
- Availability checks for files that may have moved or been removed.

### Device Linking

- Link trusted devices through a temporary code or QR code.
- Create or join a device group.
- View and manage linked devices.
- Share playback position between devices.
- Continue listening from another linked device.
- Local-network-only protection for device-linking operations.

### Downloads

- Individual and batch downloads.
- Background download support.
- Progress notifications.
- Retry and recovery for interrupted operations.
- User-selected permanent storage locations.
- Clear distinction between temporary cache and permanent downloads.

---

## Contextual Tips

NetShare Player includes optional contextual tutorials for its main screens.

Tips are available for:

- Server connection
- File browser
- Audio player
- Image viewer
- Text viewer
- Video player

Each tutorial can be skipped, replayed for an individual screen, or reset from Settings.

---

## Feedback and Support

The app includes an optional feedback form for:

- Bug reports
- Suggestions
- General questions

Reports are only submitted after explicit user confirmation. Optional diagnostics exclude server passwords, permanent device identifiers, private file paths, and server addresses.

If the device is offline, pending reports are stored locally and retried when connectivity returns.

An in-app FAQ is also available from Settings.

---

## Themes and Accessibility

- System, light, and dark theme modes.
- Live adaptation when the system theme changes.
- Persistent theme preference.
- Responsive layouts for phones and tablets.
- Contextual tutorials for hidden or gesture-based features.
- Interface translated into 10 languages.

### Supported Languages

- English
- French
- Spanish
- German
- Portuguese
- Russian
- Arabic
- Chinese
- Japanese
- Korean

---

## Remote Access Options

| Method | Difficulty | Best For |
| :--- | :---: | :--- |
| **localhost.run** | Easy | Temporary public sharing |
| **Cloudflare Tunnel** | Intermediate | Stable remote access with a custom domain |
| **Tailscale** | Easy | Private access between trusted devices |
| **ngrok** | Easy | Development and temporary access |
| **Reverse Proxy** | Advanced | Existing self-hosted infrastructure |
| **Port Forwarding** | Advanced | Permanent home-server deployments |

> Always protect remotely accessible servers with a strong password and HTTPS.

---

## Supported Formats

Actual playback support can vary depending on the device, codec, and installed applications.

| Category | Commonly Supported Formats |
| :--- | :--- |
| **Video** | MP4, MKV, AVI, MOV, WMV, FLV, WEBM, TS |
| **Audio** | MP3, FLAC, AAC, WAV, OGG, M4A, OPUS, WMA |
| **Images** | JPG, JPEG, PNG, GIF, WEBP, BMP, SVG |
| **Text** | TXT, MD, LOG, CSV, JSON, XML, YAML |
| **Documents** | PDF, DOCX, XLSX, PPTX through a compatible installed app |

---

## Installation

### NetShare Server — Windows

1. Download `NetShare.Server.exe` from the [latest GitHub release](https://github.com/Melo-Technology/NetShare-Player/releases).
2. Run the application.
3. Select the folder you want to share.
4. Configure an optional local password.
5. Start the server.

A portable build may run without installation. Installer-based releases can also be provided depending on the version.

### NetShare Player — Android

Install NetShare Player from Google Play when available, or download the APK from the [latest GitHub release](https://github.com/Melo-Technology/NetShare-Player/releases).

When installing an APK manually, Android may ask you to authorize installations from the application used to open the file.

---

## Requirements

### Server

- Windows 10 or later
- FFmpeg for advanced media analysis
- Network access through the Windows firewall
- Internet access only for remote tunnels or optional cloud integrations

### Mobile

- Android 6.0 or later
- Local-network permission for automatic discovery
- Storage or media permissions when required by the Android version

### Local Use

- Both devices connected to the same local network
- Guest Wi-Fi isolation disabled
- NetShare Server allowed through the Windows firewall

---

## Privacy

For normal local use:

- No NetShare account is required.
- Files are transferred directly between the mobile device and your computer.
- Server passwords are stored using the device’s secure storage.
- Media history remains on the mobile device.
- NetShare does not currently use Firebase Analytics or Firebase Crashlytics.
- Firebase Remote Config may retrieve application configuration.
- Feedback is sent only when the user explicitly submits a report.

Remote tunnels and optional cloud-storage integrations may route data through their respective providers.

---

## Project Structure

The NetShare ecosystem contains two main applications:

- **NetShare Server** — Python desktop server and Windows interface.
- **NetShare Player** — Flutter mobile application.

Both applications work together but have separate responsibilities: the server owns and exposes the files, while the player browses and consumes them.

---

## License

NetShare Player is distributed as freeware.

See the repository and release files for the complete license terms and redistribution restrictions.

---

<div align="center">

### Join the local revolution.

*Stop uploading. Start sharing.*

<br>

**Made with ♥ by Mélo Technology**

[melotechnology@proton.me](mailto:melotechnology@proton.me) ·
[GitHub](https://github.com/Melo-Technology) ·
[Releases](https://github.com/Melo-Technology/NetShare-Player/releases)

</div>
