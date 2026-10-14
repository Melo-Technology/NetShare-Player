"""Bounded lyrics proxy: LRCLIB first, Lyrics.ovh fallback."""

import json
import re
import time
import unicodedata
from collections import OrderedDict
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


_LEADING_NUMBER = re.compile(
    r"^\s*(?:(?:cd|disc|disk)\s*\d{1,2}\s*[-_. ]+)?\d{1,3}(?:\s*[.)\]_\-]+\s*|\s+)",
    re.IGNORECASE,
)
_QUALITY = re.compile(r"[\s_-]*\(?\[?\b\d{2,4}\s?k(?:bps|p)?\b\)?\]?", re.IGNORECASE)
_BRACKET = re.compile(r"[\(\[]([^\)\]]*)[\)\]]")
_DASH = re.compile(r"\s+[-–—]\s+")
_FEATURE = re.compile(r"\b(?:feat(?:uring)?\.?|ft\.?)\s+(.+)$", re.IGNORECASE)
_NOISE = {
    "official audio", "official video", "official music video", "music video",
    "lyrics", "lyric video", "visualizer", "audio", "video", "hq", "hd",
    "high quality", "full song", "youtube", "vevo",
}
_VERSIONS = {
    "remix", "edit", "radio edit", "extended", "extended mix", "live",
    "acoustic", "instrumental", "remastered", "remaster", "sped up",
    "slowed", "nightcore", "cover", "karaoke", "demo",
}


def parse_track_filename(filename):
    """Return a bounded artist/title guess without exposing it to the browser."""
    name = str(filename).rsplit(".", 1)[0].replace("_", " ")
    name = _LEADING_NUMBER.sub("", name, count=1)
    versions = []

    def clean_bracket(match):
        value = " ".join(match.group(1).strip().lower().split())
        if any(word == value or word in value for word in _NOISE):
            return " "
        if any(word in value for word in _VERSIONS):
            versions.append(value)
            return " "
        return match.group(0)

    name = _QUALITY.sub(" ", _BRACKET.sub(clean_bracket, name))
    name = " ".join(name.split()).strip(" -–—")
    parts = _DASH.split(name, maxsplit=1)
    artist, title = (parts[0], parts[1]) if len(parts) == 2 else ("", name)
    feature = _FEATURE.search(title)
    featured = []
    if feature:
        featured = [" ".join(feature.group(1).split())]
        title = title[:feature.start()].strip()
    if versions:
        title = f"{title} ({versions[0].title()})"
    return {
        "artist": " ".join(artist.split()),
        "title": " ".join(title.split()),
        "featured_artists": featured,
        "version_tags": versions,
    }


def resolve_lyrics_query(metadata, filename):
    guess = parse_track_filename(filename)
    stem = str(filename).rsplit(".", 1)[0]
    title = str(metadata.get("title") or "").strip()
    artist = str(metadata.get("artist") or "").strip()
    poor_title = not title or _normal(title) in {_normal(stem), "unknown", "track"}
    poor_artist = not artist or _normal(artist) in {"unknown", "unknown artist"}
    return {
        "artist": guess["artist"] if poor_artist else artist,
        "title": guess["title"] if poor_title else title,
        "album": metadata.get("album"),
        "duration": metadata.get("duration"),
    }


def _normal(value):
    ascii_value = unicodedata.normalize("NFKD", str(value)).encode("ascii", "ignore").decode()
    return " ".join(re.findall(r"[a-z0-9]+", ascii_value.casefold()))


def _candidate_score(candidate, artist, title, duration):
    wanted_artist, wanted_title = _normal(artist), _normal(title)
    got_artist = _normal(candidate.get("artistName", ""))
    got_title = _normal(candidate.get("trackName", ""))
    title_words, got_title_words = set(wanted_title.split()), set(got_title.split())
    artist_words, got_artist_words = set(wanted_artist.split()), set(got_artist.split())
    title_overlap = len(title_words & got_title_words) / max(1, len(title_words | got_title_words))
    artist_overlap = len(artist_words & got_artist_words) / max(1, len(artist_words | got_artist_words))
    score = (5 if got_title == wanted_title else 3 * title_overlap)
    score += 4 if got_artist == wanted_artist else 2 * artist_overlap
    candidate_duration = candidate.get("duration")
    if duration and isinstance(candidate_duration, (int, float)):
        delta = abs(float(duration) - float(candidate_duration))
        score += 2 if delta <= 2 else 1 if delta <= 10 else -2 if delta > 45 else 0
    return score


class LyricsService:
    def __init__(self, *, capacity=256, ttl_seconds=86400, timeout=8, clock=time.time):
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self.timeout = timeout
        self.clock = clock
        self._cache = OrderedDict()

    def lookup(self, *, artist, title, album=None, duration=None):
        key = (
            artist.strip().casefold(), title.strip().casefold(),
            (album or "").strip().casefold(), int(duration or 0),
        )
        if not key[0] or not key[1]:
            return self._missing()
        cached = self._cache.get(key)
        now = self.clock()
        if cached and cached[0] > now:
            self._cache.move_to_end(key)
            return {**cached[1], "cached": True}
        result = self._lrclib(artist, title, album, duration)
        if result is None:
            result = self._lyrics_ovh(artist, title)
        result = result or self._missing()
        self._cache[key] = (now + self.ttl_seconds, result)
        self._cache.move_to_end(key)
        while len(self._cache) > self.capacity:
            self._cache.popitem(last=False)
        return {**result, "cached": False}

    def _get_json(self, url):
        request = Request(url, headers={"User-Agent": "NetShareServer/lyrics"})
        with urlopen(request, timeout=self.timeout) as response:
            if response.status != 200:
                return None
            return json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))

    def _lrclib(self, artist, title, album, duration):
        params = {"artist_name": artist, "track_name": title}
        if album:
            params["album_name"] = album
        if duration:
            params["duration"] = str(int(duration))
        try:
            data = self._get_json("https://lrclib.net/api/get?" + urlencode(params))
            if not data:
                candidates = self._get_json("https://lrclib.net/api/search?" + urlencode({"artist_name": artist, "track_name": title}))
                if isinstance(candidates, list):
                    ranked = sorted(
                        (item for item in candidates[:20] if isinstance(item, dict)),
                        key=lambda item: _candidate_score(item, artist, title, duration),
                        reverse=True,
                    )
                    data = ranked[0] if ranked and _candidate_score(
                        ranked[0], artist, title, duration,
                    ) >= 4 else None
                else:
                    data = None
            if isinstance(data, dict):
                plain, synced = data.get("plainLyrics"), data.get("syncedLyrics")
                instrumental = bool(data.get("instrumental", False))
                if instrumental or (plain and plain.strip()) or (synced and synced.strip()):
                    return {"found": True, "plain_lyrics": plain, "synced_lyrics": synced, "instrumental": instrumental, "source": "lrclib"}
        except Exception:
            return None
        return None

    def _lyrics_ovh(self, artist, title):
        try:
            data = self._get_json(f"https://api.lyrics.ovh/v1/{quote(artist, safe='')}/{quote(title, safe='')}")
            lyrics = data.get("lyrics") if isinstance(data, dict) else None
            if lyrics and lyrics.strip():
                return {"found": True, "plain_lyrics": lyrics.strip(), "synced_lyrics": None, "instrumental": False, "source": "lyrics.ovh"}
        except Exception:
            return None
        return None

    @staticmethod
    def _missing():
        return {"found": False, "plain_lyrics": None, "synced_lyrics": None, "instrumental": False, "source": None}


lyrics_service = LyricsService()
