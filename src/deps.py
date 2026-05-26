"""
NetShare Player — Optional dependency flags
Imported once at startup; all other modules read from here.
"""

try:
    import qrcode          # noqa: F401
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    import websockets       # noqa: F401
    import websockets.server  # noqa: F401
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

try:
    from watchdog.observers import Observer           # noqa: F401
    from watchdog.events import FileSystemEventHandler  # noqa: F401
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    from PIL import Image as PilImage  # noqa: F401
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from imageio_ffmpeg import get_ffmpeg_exe as _get_ffmpeg_exe
    FFMPEG_BIN: str | None = _get_ffmpeg_exe()
    HAS_FFMPEG: bool = True
except ImportError:
    # imageio-ffmpeg not installed — fall back to system ffmpeg
    import shutil as _shutil
    FFMPEG_BIN = _shutil.which("ffmpeg") or _shutil.which("ffmpeg.exe")
    HAS_FFMPEG = FFMPEG_BIN is not None
except RuntimeError:
    # imageio-ffmpeg installed but no binary found
    import shutil as _shutil
    FFMPEG_BIN = _shutil.which("ffmpeg") or _shutil.which("ffmpeg.exe")
    HAS_FFMPEG = FFMPEG_BIN is not None