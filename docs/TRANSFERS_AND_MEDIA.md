# Transfers, streaming, and FFmpeg

## File transfers

NetShare supports direct files and HTTP range requests for normal playback and download resumption. Resumable multi-file sessions track an expected manifest and received chunks. Sizes, offsets, hashes, and paths are validated, and completed files are published through an atomic rename.

Temporary share links use random tokens while storing only token hashes. They have a lifetime, scope, permissions, and access limits. Public uploads require host approval and enforce size, extension, rate, and count limits before data is written.

## HLS transcoding

Adaptive streaming creates short media segments on demand and caches validated output. FFmpeg is executed without a shell, with bounded output, timeouts, concurrency limits, and private cache limits. A failed or timed-out generation never becomes a valid cache entry.

If FFmpeg is unavailable, direct downloads and direct streaming remain available, while features that require transcoding or probing are disabled.

## Installing FFmpeg

NetShare uses a system-provided FFmpeg installation and does not download a binary from the settings screen.

On Windows, install a build linked from the [official FFmpeg download page](https://ffmpeg.org/download.html) and add the directory containing `ffmpeg.exe` and `ffprobe.exe` to `PATH`.

On macOS:

```bash
brew install ffmpeg
```

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install ffmpeg
```

On Fedora:

```bash
sudo dnf install ffmpeg
```

On Arch Linux:

```bash
sudo pacman -S ffmpeg
```

Verify the installation in a new terminal:

```bash
ffmpeg -version
ffprobe -version
```

If FFmpeg is outside `PATH`, set its executable path in **Settings > FFmpeg** and run the validation again. NetShare checks the required encoders, muxers, and filters; command availability alone does not guarantee every media feature.

## Cloud media

Cloud providers share a common listing and reading interface. OAuth providers use PKCE and loopback callbacks, tokens are stored through the secure token store, and provider errors shown in the UI are stripped of credentials. Cloud listings and derived media data use bounded caches.
