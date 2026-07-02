#!/usr/bin/env python3
"""
auto_recorder.py — Automatic endpoint discovery and trace recording for RRFuzz.

Usage:
    python3 auto_recorder.py \
        --qemu /path/to/qemu-mipsel \
        --target /path/to/httpd \
        --sim-root /path/to/rootfs \
        --output /tmp/auto_traces \
        [--port 8099] \
        [--max-endpoints 20]

For each discovered endpoint the recorder will:
  1. Start the target binary under QEMU in RR record mode on a free port.
  2. Send a GET (and for .cgi/.asp/.php/.do paths also a POST) request.
  3. Gracefully stop QEMU and verify the trace file is > 1 KB.
  4. Save valid traces to --output directory.

Endpoint discovery order:
  a. Binary strings matching URL path pattern (/[a-zA-Z0-9_./-]+)
  b. href/action attributes in sim_root HTML files
  c. Paths referenced in config files (*.conf, *.cfg) inside sim_root
  (No external wordlist — keeps it simple.)

Auth handling (HTTP Basic only):
  If GET / returns 401 with WWW-Authenticate: Basic, try default creds.
  Everything else is recorded unauthenticated (pre-auth traces are also useful).
"""

import argparse
import hashlib
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# Endpoint Discovery
# ---------------------------------------------------------------------------

_URL_PAT = re.compile(rb'/[a-zA-Z0-9_./%\-]{2,127}')
_HREF_PAT = re.compile(rb'(?:href|action|src)\s*=\s*["\']([^"\']{1,128})["\']', re.IGNORECASE)

_SKIP_EXT = {'.o', '.c', '.h', '.so', '.a', '.ko', '.map', '.d', '.S',
             '.txt', '.md', '.log', '.bin', '.img', '.gz', '.tar'}


_VALID_PATH_PAT = re.compile(r'^/[a-zA-Z0-9_./%\-]{2,127}$')

def _discover_from_binary(binary_path: str) -> List[str]:
    """Extract candidate URL paths from printable strings in the binary."""
    paths = set()
    try:
        result = subprocess.run(
            ['strings', '-n', '4', binary_path],
            capture_output=True, timeout=30
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            # Use only the matched portion (not the whole line)
            m = _URL_PAT.match(line)
            if not m:
                continue
            p = m.group(0).decode('latin1', errors='ignore')
            # Strict validity: must pass the clean URL pattern (no templates, spaces, etc.)
            if not _VALID_PATH_PAT.match(p):
                continue
            # skip paths that look like source / library artefacts
            if any(p.endswith(ext) for ext in _SKIP_EXT):
                continue
            if p.count('/') > 8:
                continue
            paths.add(p)
    except Exception as e:
        print(f"[AutoRecorder] strings extraction failed: {e}")
    return sorted(paths)


def _discover_from_simroot(sim_root: str) -> List[str]:
    """Scan HTML and config files in sim_root for URL paths."""
    paths = set()
    root = Path(sim_root)

    # HTML files
    for pattern in ('**/*.htm', '**/*.html', '**/*.asp', '**/*.cgi'):
        for f in root.glob(pattern):
            try:
                content = f.read_bytes()[:65536]
                for m in _HREF_PAT.finditer(content):
                    url = m.group(1).decode('latin1', errors='ignore')
                    # Normalize and strip query string
                    if url.startswith('/'):
                        candidate = url.split('?')[0]
                    elif url and not url.startswith(('http', '#', 'javascript', '<', '+')):
                        candidate = '/' + url.lstrip('/').split('?')[0]
                    else:
                        continue
                    # Only keep clean URL paths (no template syntax, spaces, brackets)
                    if _VALID_PATH_PAT.match(candidate):
                        paths.add(candidate)
            except Exception:
                pass

    # Config files
    for pattern in ('**/*.conf', '**/*.cfg', '**/*.ini'):
        for f in root.glob(pattern):
            try:
                content = f.read_text('latin1', errors='ignore')
                for m in re.finditer(r'["\']?(/[a-zA-Z0-9_./%\-]{2,80})["\']?', content):
                    p = m.group(1)
                    if any(p.endswith(ext) for ext in _SKIP_EXT):
                        continue
                    paths.add(p)
            except Exception:
                pass

    return sorted(paths)


def discover_endpoints(binary_path: str, sim_root: Optional[str] = None,
                       max_endpoints: int = 30) -> List[str]:
    """Return a deduplicated list of candidate URL paths."""
    paths: set = set()
    paths.add('/')  # always include root

    paths.update(_discover_from_binary(binary_path))
    if sim_root:
        paths.update(_discover_from_simroot(sim_root))

    # Filter: keep paths that could be HTTP endpoints
    filtered = []
    for p in sorted(paths):
        if '://' in p:
            continue
        if not p.startswith('/'):
            continue
        if '..' in p:
            continue
        if '_files/' in p:
            continue
        filtered.append(p)

    # Prioritize: CGI/ASP endpoints first, then others (so cap favors actionable paths)
    cgi_paths = [p for p in filtered if is_cgi_path(p)]
    other_paths = [p for p in filtered if not is_cgi_path(p)]
    ordered = cgi_paths + other_paths

    print(f"[AutoRecorder] Discovered {len(ordered)} candidate endpoints "
          f"({len(cgi_paths)} CGI/ASP, capped at {max_endpoints})")
    return ordered[:max_endpoints]


# ---------------------------------------------------------------------------
# Auth Probing (HTTP Basic only)
# ---------------------------------------------------------------------------

_DEFAULT_CREDS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', ''),
    ('root', 'root'),
    ('root', 'admin'),
    ('user', 'user'),
]


def _wait_for_port(host: str, port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def probe_auth(host: str, port: int) -> dict:
    """
    Returns {'needs_auth': bool, 'creds': (user, pass) | None}.
    Only handles HTTP Basic; everything else treated as 'no auth found'.
    """
    try:
        import urllib.request
        import urllib.error
        url = f'http://{host}:{port}/'
        try:
            urllib.request.urlopen(url, timeout=5)
            return {'needs_auth': False, 'creds': None}
        except urllib.error.HTTPError as e:
            if e.code != 401:
                return {'needs_auth': False, 'creds': None}
            auth_hdr = e.headers.get('WWW-Authenticate', '')
            if 'Basic' not in auth_hdr and 'basic' not in auth_hdr:
                print(f"[AutoRecorder] 401 but non-Basic auth ({auth_hdr!r}), recording pre-auth only")
                return {'needs_auth': True, 'creds': None}
            # Try default creds
            import base64
            for user, pwd in _DEFAULT_CREDS:
                token = base64.b64encode(f'{user}:{pwd}'.encode()).decode()
                req = urllib.request.Request(url)
                req.add_header('Authorization', f'Basic {token}')
                try:
                    urllib.request.urlopen(req, timeout=5)
                    print(f"[AutoRecorder] Auth success: {user}:{pwd}")
                    return {'needs_auth': True, 'creds': (user, pwd)}
                except urllib.error.HTTPError as e2:
                    if e2.code == 401:
                        continue
                    # non-401 means auth worked
                    return {'needs_auth': True, 'creds': (user, pwd)}
            print("[AutoRecorder] Could not guess Basic creds, recording pre-auth only")
            return {'needs_auth': True, 'creds': None}
        except Exception:
            return {'needs_auth': False, 'creds': None}
    except Exception as ex:
        print(f"[AutoRecorder] probe_auth error: {ex}")
        return {'needs_auth': False, 'creds': None}


# ---------------------------------------------------------------------------
# Trace Recording
# ---------------------------------------------------------------------------

def _find_free_port(start: int = 8200) -> int:
    for port in range(start, start + 200):
        try:
            with socket.socket() as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('', port))
                return port
        except OSError:
            continue
    raise RuntimeError("No free port found in range")


def _build_env(qemu_ld_prefix: str, trace_path: str) -> dict:
    env = {'RR_MODE': 'record', 'RR_TRACE_FILE': trace_path}
    if qemu_ld_prefix:
        env['QEMU_LD_PREFIX'] = qemu_ld_prefix
    # Pass through PATH so QEMU can find helpers
    env['PATH'] = os.environ.get('PATH', '/usr/bin:/bin')
    return env


def _send_request(host: str, port: int, path: str, method: str = 'GET',
                  creds: Optional[Tuple[str, str]] = None,
                  body: Optional[bytes] = None) -> bool:
    """Send one HTTP request. Returns True if a response (any) was received."""
    import urllib.request
    import urllib.error
    import base64

    url = f'http://{host}:{port}{path}'
    data = body if method == 'POST' else None
    req = urllib.request.Request(url, data=data, method=method)
    if creds:
        token = base64.b64encode(f'{creds[0]}:{creds[1]}'.encode()).decode()
        req.add_header('Authorization', f'Basic {token}')
    if data:
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Content-Length', str(len(data)))
    try:
        urllib.request.urlopen(req, timeout=6)
        return True
    except urllib.error.HTTPError:
        return True   # HTTP error is still a response — trace was recorded
    except Exception:
        return False


def record_one_trace(qemu_path: str, target_binary: str, sim_root: Optional[str],
                     trace_path: str, port: int, path: str, method: str = 'GET',
                     creds: Optional[Tuple[str, str]] = None,
                     body: Optional[bytes] = None,
                     startup_timeout: float = 8.0,
                     request_timeout: float = 10.0) -> bool:
    """
    Record one trace for (method, path).
    Returns True if a valid trace (>1 KB) was produced.
    """
    env = _build_env(sim_root or '', trace_path)

    cmd = [qemu_path]
    if sim_root:
        cmd += ['-L', sim_root]
    cmd += [target_binary, '-p', str(port)]

    proc = subprocess.Popen(cmd, env=env,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    try:
        if not _wait_for_port('127.0.0.1', port, timeout=startup_timeout):
            print(f"[AutoRecorder] Target did not bind on port {port} within {startup_timeout}s")
            return False

        ok = _send_request('127.0.0.1', port, path, method=method, creds=creds, body=body)
        time.sleep(0.5)  # let the response flush and trace write complete
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=4)
        except Exception:
            proc.kill()

    trace = Path(trace_path)
    if trace.exists() and trace.stat().st_size > 1024:
        return True
    trace.unlink(missing_ok=True)
    return False


# ---------------------------------------------------------------------------
# Batch Recording
# ---------------------------------------------------------------------------

_CGI_EXTS = {'.cgi', '.asp', '.php', '.do', '.action', '.pl', '.py', '.lua'}


def is_cgi_path(path: str) -> bool:
    suffix = Path(path.split('?')[0]).suffix.lower()
    return suffix in _CGI_EXTS or '/cgi' in path.lower()


def record_batch(qemu_path: str, target_binary: str, sim_root: Optional[str],
                 output_dir: str, endpoints: List[str],
                 auth_info: Optional[dict] = None,
                 startup_timeout: float = 8.0) -> List[str]:
    """
    Record traces for a batch of endpoints.
    Returns list of successfully recorded trace file paths.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    creds = (auth_info or {}).get('creds')
    traces = []

    for url_path in endpoints:
        path_hash = hashlib.md5(url_path.encode()).hexdigest()[:8]

        # --- GET ---
        port = _find_free_port()
        trace_path = str(out / f'GET_{path_hash}.trace')
        print(f"[AutoRecorder] Recording GET {url_path} → {trace_path}")
        ok = record_one_trace(
            qemu_path, target_binary, sim_root,
            trace_path, port, url_path,
            method='GET', creds=creds,
            startup_timeout=startup_timeout,
        )
        if ok:
            print(f"[AutoRecorder]   OK ({Path(trace_path).stat().st_size} bytes)")
            traces.append(trace_path)
        else:
            print(f"[AutoRecorder]   FAILED or empty trace, skipping")

        # --- POST (CGI-like paths only) ---
        if is_cgi_path(url_path):
            port = _find_free_port()
            trace_path_post = str(out / f'POST_{path_hash}.trace')
            print(f"[AutoRecorder] Recording POST {url_path} → {trace_path_post}")
            ok_post = record_one_trace(
                qemu_path, target_binary, sim_root,
                trace_path_post, port, url_path,
                method='POST', creds=creds,
                body=b'dummy=1',
                startup_timeout=startup_timeout,
            )
            if ok_post:
                print(f"[AutoRecorder]   OK POST ({Path(trace_path_post).stat().st_size} bytes)")
                traces.append(trace_path_post)
            else:
                print(f"[AutoRecorder]   POST FAILED or empty, skipping")

    return traces


# ---------------------------------------------------------------------------
# Top-level AutoRecorder
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Trace Fingerprint Clustering
# ---------------------------------------------------------------------------

def _trace_fingerprint(trace_path: str) -> Optional[tuple]:
    """
    Compute a structural fingerprint for a trace:
      (syscall_count, accept_index, frozenset of network-fd-related syscall names)

    Traces with the same fingerprint cover essentially the same code path and
    can be reduced to a single representative.
    """
    try:
        import sys as _sys
        _here = Path(__file__).resolve().parent.parent
        if str(_here) not in _sys.path:
            _sys.path.insert(0, str(_here))
        from conductor.trace_analyzer import TraceAnalyzer
        ta = TraceAnalyzer(trace_path)
        syscalls = ta.syscalls
        if not syscalls:
            return None

        n = len(syscalls)
        accept_idx = 0
        for sc in syscalls:
            if sc.name in ('accept', 'accept4') or (
                    sc.name == 'socketcall' and sc.args and sc.args[0] in (5, 18)):
                accept_idx = sc.index
                break

        # Post-accept syscall name multiset → frozenset of (name, count) pairs
        # Bucket counts into coarse bins (1, 2-4, 5-15, 16+) to tolerate minor variation
        from collections import Counter
        _COARSE = lambda c: 1 if c == 1 else (2 if c <= 4 else (3 if c <= 15 else 4))
        post_names = Counter(sc.name for sc in syscalls if sc.index > accept_idx)
        name_sig = frozenset((name, _COARSE(cnt)) for name, cnt in post_names.items())

        # Bin syscall count: coarse bucket so near-identical traces cluster
        count_bucket = n // 20  # bucket width = 20 syscalls

        return (count_bucket, accept_idx // 5, name_sig)  # accept_idx also bucketed
    except Exception:
        return None


def deduplicate_traces(trace_paths: List[str],
                       keep_methods: bool = True) -> List[str]:
    """
    Given a list of trace paths, return a deduplicated subset where each
    structural fingerprint cluster is represented by exactly one trace.

    If keep_methods=True, within a cluster prefer POST over GET (more interesting).
    Traces whose fingerprint can't be computed are kept as-is.

    Returns the deduplicated list (preserves original order of first-seen per cluster).
    """
    seen: dict = {}    # fingerprint → best trace path
    unanalyzed: List[str] = []

    for path in trace_paths:
        fp = _trace_fingerprint(path)
        if fp is None:
            unanalyzed.append(path)
            continue
        if fp not in seen:
            seen[fp] = path
        else:
            # Prefer POST over GET within same cluster
            existing = seen[fp]
            if keep_methods and '/POST_' in Path(path).name and '/GET_' in Path(existing).name:
                seen[fp] = path

    result = list(seen.values()) + unanalyzed
    print(f"[AutoRecorder] Dedup: {len(trace_paths)} traces → {len(result)} unique "
          f"({len(trace_paths) - len(result)} duplicates removed)")
    return result


class AutoRecorder:
    def __init__(self, qemu_path: str, target_binary: str,
                 sim_root: Optional[str], output_dir: str):
        self.qemu_path = qemu_path
        self.target_binary = target_binary
        self.sim_root = sim_root
        self.output_dir = output_dir

    def run(self, max_endpoints: int = 25, auth_probe_port: int = 8099,
            startup_timeout: float = 8.0, deduplicate: bool = True) -> List[str]:
        """
        Full pipeline: discover endpoints → probe auth → record traces → deduplicate.
        Returns list of valid, deduplicated trace file paths.
        """
        endpoints = discover_endpoints(self.target_binary, self.sim_root, max_endpoints)

        # Probe auth using the first endpoint (root /)
        print(f"[AutoRecorder] Probing auth on port {auth_probe_port}...")
        port = _find_free_port(auth_probe_port)
        env = _build_env(self.sim_root or '', '/dev/null')
        # start target briefly just for auth probe (no recording)
        env_copy = dict(env)
        env_copy['RR_MODE'] = ''  # no recording for probe
        del env_copy['RR_TRACE_FILE']

        probe_proc = subprocess.Popen(
            [self.qemu_path] + (['-L', self.sim_root] if self.sim_root else []) +
            [self.target_binary, '-p', str(port)],
            env={**os.environ, **env_copy},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        auth_info = {'needs_auth': False, 'creds': None}
        try:
            if _wait_for_port('127.0.0.1', port, timeout=8.0):
                auth_info = probe_auth('127.0.0.1', port)
        finally:
            try:
                probe_proc.send_signal(signal.SIGTERM)
                probe_proc.wait(timeout=4)
            except Exception:
                probe_proc.kill()

        print(f"[AutoRecorder] Auth info: {auth_info}")

        traces = record_batch(
            self.qemu_path, self.target_binary, self.sim_root,
            self.output_dir, endpoints, auth_info,
            startup_timeout=startup_timeout,
        )

        print(f"\n[AutoRecorder] Recorded {len(traces)} valid traces in {self.output_dir}")

        if deduplicate and len(traces) > 1:
            traces = deduplicate_traces(traces)

        print(f"[AutoRecorder] Final: {len(traces)} traces ready for fuzzing")
        return traces


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='RRFuzz auto trace recorder')
    parser.add_argument('--qemu', required=True, help='Path to QEMU binary')
    parser.add_argument('--target', required=True, help='Path to target binary')
    parser.add_argument('--sim-root', default=None, help='Path to rootfs / sim_root')
    parser.add_argument('--output', required=True, help='Output directory for traces')
    parser.add_argument('--max-endpoints', type=int, default=25,
                        help='Maximum number of endpoints to probe (default: 25)')
    parser.add_argument('--startup-timeout', type=float, default=8.0,
                        help='Seconds to wait for target to bind port (default: 8)')
    parser.add_argument('--no-dedup', action='store_true',
                        help='Disable trace deduplication (keep all recorded traces)')
    args = parser.parse_args()

    recorder = AutoRecorder(
        qemu_path=args.qemu,
        target_binary=args.target,
        sim_root=args.sim_root,
        output_dir=args.output,
    )
    traces = recorder.run(
        max_endpoints=args.max_endpoints,
        startup_timeout=args.startup_timeout,
        deduplicate=not args.no_dedup,
    )
    print(f"\nRecorded traces:")
    for t in traces:
        print(f"  {t}")
    sys.exit(0 if traces else 1)


if __name__ == '__main__':
    main()
