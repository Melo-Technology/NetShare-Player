"""Typed failures owned by the desktop shell integration layer."""


class DesktopShellError(RuntimeError):
    """Base exception for shell-specific startup/integration failures."""


class DesktopShellDependencyError(DesktopShellError):
    """Raised when the optional native PyWebView dependency is unavailable."""


class DesktopShellAssetError(DesktopShellError):
    """Raised when packaged/local shell assets cannot be resolved safely."""
