"""
NetShare Player — Theme system
Monochrome dark / light palettes with live-swap accessors.
"""

_DARK = {
    "BG":        "#000000",
    "SURFACE":   "#0f0f0f",
    "SURFACE2":  "#202020",
    "BORDER":    "#464646",
    "BORDER2":   "#5c5c5c",
    "FG":        "#ffffff",
    "FG2":       "#d0d0d0",
    "FG3":       "#9a9a9a",
    "DANGER":    "#ff3333",
    "TOGGLE_BG": "#202020",
    "TOGGLE_FG": "#d0d0d0",
}

_LIGHT = {
    "BG":        "#f5f5f5",
    "SURFACE":   "#ffffff",
    "SURFACE2":  "#dddddd",
    "BORDER":    "#a8a8a8",
    "BORDER2":   "#7a7a7a",
    "FG":        "#000000",
    "FG2":       "#242424",
    "FG3":       "#555555",
    "DANGER":    "#b00000",
    "TOGGLE_BG": "#dddddd",
    "TOGGLE_FG": "#242424",
}

# Active palette — mutated in-place on theme toggle so all accessors
# always reflect the current theme without re-import.
_theme: dict = dict(_DARK)


def BG()       : return _theme["BG"]
def SURFACE()  : return _theme["SURFACE"]
def SURFACE2() : return _theme["SURFACE2"]
def BORDER()   : return _theme["BORDER"]
def FG()       : return _theme["FG"]
def FG2()      : return _theme["FG2"]
def FG3()      : return _theme["FG3"]
def DANGER()   : return _theme["DANGER"]
