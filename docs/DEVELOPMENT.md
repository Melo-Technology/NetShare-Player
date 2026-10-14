# Development and testing

The test suite uses pytest and `unittest.TestCase` and covers core services, routes, HTTP and TLS security, clustering, storage, the desktop interface, localization, tunnels, media, and transfers.

## Run the test suite

```powershell
python -m pytest -q --basetemp .pytest-local
```

Examples of focused runs:

```powershell
python -m pytest -q tests/test_cluster_fallback.py --basetemp .pytest-cluster-local
python -m pytest -q tests/test_server_tls.py tests/test_server_tls_transport.py --basetemp .pytest-tls-local
```

Network and platform behavior should also be validated on real machines. Unit tests cannot fully reproduce multicast DNS, firewalls, OS key stores, or native WebView behavior.

## Packaging

Platform builds package `frontend/` and all local assets. Runtime operation must not depend on a CDN.

- Windows: `python packaging/build_pyinstaller.py`, followed by Inno Setup
- macOS: `bash packaging/build_dmg.sh`
- Linux: `bash packaging/build_appimage.sh`

Before publishing a release, run the complete automated suite, relevant TLS and cluster socket tests, an FFmpeg smoke test when available, and a native UI smoke test on every supported operating system.
