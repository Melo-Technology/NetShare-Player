"""GPU rate-control arguments shared by capability probes and HLS encoding.

Keep this module dependency-free: deps probes at import time, before the
adaptive streaming service can be imported safely.
"""


def gpu_encoder_arguments(encoder: str, bandwidth: int, backend: str) -> list[str]:
    if backend == "nvenc":
        options = ["-preset", "p4", "-tune", "hq", "-rc", "vbr"]
    elif backend == "qsv":
        options = ["-preset", "medium"]
    elif backend == "amf":
        options = ["-usage", "transcoding", "-quality", "balanced", "-rc", "vbr_peak"]
    elif backend == "videotoolbox":
        options = ["-allow_sw", "0"]
    else:
        raise ValueError("unsupported GPU backend")
    return [
        "-c:v", encoder, *options,
        "-pix_fmt", "nv12",
        "-b:v", str(bandwidth),
        "-maxrate", str(max(bandwidth, int(bandwidth * 1.15))),
        "-bufsize", str(bandwidth * 2),
    ]
