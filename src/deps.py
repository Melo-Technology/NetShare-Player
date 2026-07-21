"""Runtime feature detection for optional dependencies used by the server."""

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
    import shutil as _shutil
    FFMPEG_BIN = _shutil.which("ffmpeg") or _shutil.which("ffmpeg.exe")
    HAS_FFMPEG = FFMPEG_BIN is not None
except RuntimeError:
    import shutil as _shutil
    FFMPEG_BIN = _shutil.which("ffmpeg") or _shutil.which("ffmpeg.exe")
    HAS_FFMPEG = FFMPEG_BIN is not None

try:
    import firebase_admin                           # noqa: F401
    from firebase_admin import credentials          # noqa: F401
    from firebase_admin import remote_config        # noqa: F401
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False

try:
    import requests  # noqa: F401
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from cryptography.fernet import Fernet  # noqa: F401
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

import shutil as _shutil
MEGATOOLS_BIN: str | None = _shutil.which("megatools") or _shutil.which("megatools.exe")
HAS_MEGATOOLS: bool = MEGATOOLS_BIN is not None
MEGATOOLS_DOWNLOAD_URL = "https://megatools.megous.com/"