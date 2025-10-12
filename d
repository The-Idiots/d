"""
weave_setup.py

Behavior:
- Creates hidden folder C:\weave1121 with subfolder logs
- Uses yt-dlp Python module to detect the extractor/platform for a URL (no domain heuristics)
  - If yt-dlp Python module not available, the script will download yt-dlp.exe (if needed) and try to
    use it to obtain metadata for the URL (as a fallback).
- Installs psutil automatically if missing (uses: python -m pip install psutil --user)
  - If installation fails, network sampling is disabled but the script continues.
- Downloads video(s) to %USERPROFILE%\Downloads (or ~/Downloads fallback)
- Writes full logs into the hidden folder logs subfolder
- Attempts VPN connect via rasdial if VPN_NAME is set (best-effort)
- Requires Windows NT-based OS, Windows 8+ (or 10+) — checks version and exits otherwise
"""

import os
import sys
import ctypes
import subprocess
import json
import threading
import time
import urllib.request
import shutil
import platform
from datetime import datetime
from urllib.parse import urlparse

# -------- CONFIG --------
WEAVE_ROOT = r"C:\weave1121"
LOGS_DIR = os.path.join(WEAVE_ROOT, "logs")
YTDLP_PATH = os.path.join(WEAVE_ROOT, "yt-dlp.exe")
YTDLP_DOWNLOAD_URL = "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.exe"
DOWNLOAD_TIMEOUT = 60  # seconds
NETWORK_SAMPLE_INTERVAL = 0.5  # seconds
VPN_NAME = ""  # e.g., "MyVPN" or leave empty
# ------------------------

# -------- Logging helper --------
def log(msg, level="INFO"):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    line = f"[{ts}] [{level}] {msg}"
    # Print to console for immediate feedback
    print(line)
    # Append to daily log file (best-effort)
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        fname = os.path.join(LOGS_DIR, f"log_{datetime.utcnow().strftime('%Y%m%d')}.txt")
        with open(fname, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        # Don't raise; logging must be best-effort
        pass

# -------- Windows-only guard --------
if os.name != "nt":
    print("This script is for Windows only. Exiting.")
    sys.exit(1)

# -------- Admin utilities --------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin():
    if is_admin():
        return True
    params = " ".join([f'"{p}"' for p in sys.argv])
    try:
        # Use ShellExecuteW runas to prompt UAC
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        return None  # indicates elevated process launched
    except Exception as e:
        log(f"Could not elevate to admin: {e}", level="WARNING")
        return False

# -------- Prepare folder --------
def prepare_folder():
    try:
        os.makedirs(WEAVE_ROOT, exist_ok=True)
        os.makedirs(LOGS_DIR, exist_ok=True)
    except Exception as e:
        log(f"Failed to create folders: {e}", level="WARNING")
    # Try to set hidden attribute (best-effort)
    try:
        # attrib expects a string when shell=True
        subprocess.check_call(f'attrib +h "{WEAVE_ROOT}"', shell=True)
    except Exception as e:
        log(f"Failed to set hidden attribute on {WEAVE_ROOT}: {e}", level="WARNING")

# -------- OS check --------
def check_kernel_and_windows_version():
    try:
        plat = platform.platform()
        windows_ver = sys.getwindowsversion()
        major = windows_ver.major
        minor = windows_ver.minor
        if "Windows" not in plat:
            log(f"OS check failed: not Windows ({plat})", level="ERROR")
            return False, plat
        # Windows 8 is NT 6.2 -> require (major==6 and minor>=2) or major>=10
        if (major == 6 and minor >= 2) or (major >= 10):
            log(f"OS check passed: platform={plat}, version={major}.{minor}")
            return True, plat
        else:
            log(f"OS version too old: {major}.{minor}. Need Windows 8 or newer.", level="ERROR")
            return False, plat
    except Exception as e:
        log(f"OS check error: {e}", level="ERROR")
        return False, "unknown"

# -------- yt-dlp management --------
def download_yt_dlp_exe():
    log(f"Downloading yt-dlp executable to {YTDLP_PATH} from {YTDLP_DOWNLOAD_URL}")
    temp_path = YTDLP_PATH + ".download"
    try:
        with urllib.request.urlopen(YTDLP_DOWNLOAD_URL, timeout=DOWNLOAD_TIMEOUT) as resp:
            with open(temp_path, "wb") as out:
                shutil.copyfileobj(resp, out)
        os.replace(temp_path, YTDLP_PATH)
        try:
            os.chmod(YTDLP_PATH, 0o755)
        except Exception:
            pass
        log("Downloaded yt-dlp.exe successfully.")
        return True
    except Exception as e:
        log(f"Failed to download yt-dlp.exe: {e}", level="ERROR")
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        return False

def get_yt_dlp_module_version():
    try:
        import yt_dlp as ytdl_mod
        ver = getattr(ytdl_mod, "__version__", None)
        if ver:
            log(f"yt_dlp Python module detected: version {ver}")
            return ver
    except Exception as e:
        log(f"yt_dlp Python module not available: {e}", level="WARNING")
    return None

# Use yt-dlp Python module to detect extractor/platform for URL.
# Falls back to yt-dlp.exe (downloaded) by calling it with --dump-single-json.
def detect_platform_with_yt_dlp(url):
    # Validate url quick
    if not validate_url(url):
        return None, "Invalid URL"

    # Try Python module first
    try:
        import yt_dlp as yt
        ydl_opts = {"quiet": True, "skip_download": True}
        with yt.YoutubeDL(ydl_opts) as ydl:
            try:
                info = ydl.extract_info(url, download=False)
                # extract extractor info
                extractor = info.get("extractor") or info.get("extractor_key") or info.get("ie_key") or info.get("uploader") or info.get("id")
                # Prefer a human-friendly extractor_key if available
                extractor_key = info.get("extractor_key") or info.get("extractor") or None
                # build platform string
                platform_name = extractor_key or extractor or "Unknown"
                log(f"Detected platform via yt-dlp Python module: {platform_name}")
                return platform_name, None
            except Exception as e:
                log(f"yt-dlp (module) failed to extract info: {e}", level="WARNING")
                # fall through to exe fallback
    except Exception as e:
        log(f"yt-dlp module import failed: {e}", level="WARNING")

    # Fallback: use executable if present - download if needed
    if not os.path.exists(YTDLP_PATH):
        log("yt-dlp.exe not found; attempting to download it as fallback.")
        got = download_yt_dlp_exe()
        if not got:
            return None, "yt-dlp module and exe unavailable"

    # Use yt-dlp.exe to dump JSON metadata
    try:
        args = [YTDLP_PATH, "--no-warnings", "--skip-download", "--dump-single-json", url]
        proc = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            log(f"yt-dlp.exe returned non-zero code while dumping JSON: {proc.returncode}. stderr: {proc.stderr}", level="WARNING")
            # maybe the exe can't run; bail
            return None, "yt-dlp.exe failed"
        stdout = proc.stdout.strip()
        if not stdout:
            log("yt-dlp.exe produced no JSON output.", level="WARNING")
            return None, "no metadata"
        try:
            info = json.loads(stdout)
            extractor_key = info.get("extractor_key") or info.get("extractor") or None
            platform_name = extractor_key or info.get("uploader") or info.get("id") or "Unknown"
            log(f"Detected platform via yt-dlp.exe: {platform_name}")
            return platform_name, None
        except Exception as e:
            log(f"Failed to parse yt-dlp.exe JSON output: {e}", level="WARNING")
            return None, "bad json"
    except subprocess.TimeoutExpired:
        log("yt-dlp.exe metadata call timed out.", level="WARNING")
        return None, "timeout"
    except Exception as e:
        log(f"Error running yt-dlp.exe to detect platform: {e}", level="WARNING")
        return None, "error"

# -------- URL validation --------
def validate_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc != ""
    except Exception:
        return False

# -------- psutil auto-install and sampler --------
def ensure_psutil_installed():
    """
    Try import psutil. If missing, attempt to install with pip (--user).
    Returns True if psutil can be imported after this call, False otherwise.
    """
    try:
        import psutil  # noqa: F401
        log("psutil already installed.")
        return True
    except ImportError:
        log("psutil not installed. Attempting to install with pip (--user).")
        try:
            cmd = [sys.executable, "-m", "pip", "install", "psutil", "--user"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if proc.returncode == 0:
                log("psutil installed via pip successfully.")
                try:
                    import psutil  # noqa: F401
                    return True
                except Exception as e:
                    log(f"Import after install failed: {e}", level="WARNING")
                    return False
            else:
                log(f"pip install psutil failed (code {proc.returncode}). stdout: {proc.stdout}; stderr: {proc.stderr}", level="WARNING")
                return False
        except subprocess.TimeoutExpired:
            log("pip install psutil timed out.", level="WARNING")
            return False
        except Exception as e:
            log(f"Failed to run pip to install psutil: {e}", level="WARNING")
            return False
    except Exception as e:
        log(f"Unexpected error checking psutil: {e}", level="WARNING")
        return False

def network_sampler(stop_event, stats_list):
    # psutil should have been ensured by caller, but check again
    try:
        import psutil
    except Exception:
        log("psutil not available in sampler; skipping network sampling.", level="WARNING")
        return

    try:
        prev = psutil.net_io_counters(pernic=True)
        last_time = time.time()
    except Exception as e:
        log(f"psutil.net_io_counters failed to initialize: {e}", level="WARNING")
        return

    while not stop_event.is_set():
        try:
            time.sleep(NETWORK_SAMPLE_INTERVAL)
            cur = psutil.net_io_counters(pernic=True)
            now = time.time()
            dt = now - last_time if now - last_time > 0 else 1.0
            total_prev = 0
            total_cur = 0
            total_errs_prev = 0
            total_errs_cur = 0
            for iface, vcur in cur.items():
                if iface.lower().startswith(("loopback", "lo")):
                    continue
                vprev = prev.get(iface)
                if not vprev:
                    continue
                total_prev += getattr(vprev, "bytes_recv", 0) + getattr(vprev, "bytes_sent", 0)
                total_cur += getattr(vcur, "bytes_recv", 0) + getattr(vcur, "bytes_sent", 0)
                total_errs_prev += getattr(vprev, "errin", 0) + getattr(vprev, "errout", 0)
                total_errs_cur += getattr(vcur, "errin", 0) + getattr(vcur, "errout", 0)
            bytes_delta = total_cur - total_prev
            errs_delta = total_errs_cur - total_errs_prev
            bw = bytes_delta / dt
            stats_list.append({"time": now, "bw_Bps": bw, "errs_delta": errs_delta})
            prev = cur
            last_time = now
        except Exception as e:
            log(f"Error during network sampling: {e}", level="WARNING")
            # continue looping unless stop_event is set

# -------- Download using yt-dlp (module preferred) --------
def run_yt_dlp_download(url, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    logfname = os.path.join(LOGS_DIR, f"yt-dlp_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log")
    log(f"Starting yt-dlp download for URL: {url} -> {out_dir}. Log file: {logfname}")

    # Decide whether to use Python module or exe
    use_python_pkg = False
    try:
        import yt_dlp as yt  # noqa: F401
        use_python_pkg = True
    except Exception:
        use_python_pkg = False

    # Ensure psutil available (install if needed) before sampler thread
    psutil_ok = ensure_psutil_installed()
    stats_list = []
    stop_event = threading.Event()
    if psutil_ok:
        sampler_thread = threading.Thread(target=network_sampler, args=(stop_event, stats_list), daemon=True)
        sampler_thread.start()
    else:
        sampler_thread = None
        log("Network sampling disabled (psutil unavailable).", level="WARNING")

    try:
        if use_python_pkg:
            import yt_dlp as yt
            ydl_opts = {
                "outtmpl": os.path.join(out_dir, "%(title)s.%(ext)s"),
                "noplaylist": False,
                "quiet": True,
                "no_warnings": True,
                "progress_hooks": [],
            }
            def hook(d):
                # log raw hook dict to file
                try:
                    with open(logfname, "a", encoding="utf-8") as lf:
                        lf.write(json.dumps(d, default=str) + "\n")
                except Exception:
                    pass
                status = d.get("status")
                if status == "downloading":
                    downloaded = d.get("downloaded_bytes") or 0
                    total = d.get("total_bytes") or d.get("total_bytes_estimate") or 0
                    speed = d.get("speed") or 0
                    percent = (downloaded / total * 100) if total else 0
                    line = f"[PROGRESS] {percent:6.2f}% {downloaded//1024}KiB at {speed/1024 if speed else 0:.2f}KiB/s"
                    print("\n" + "="*80)
                    print(line)
                    print("="*80)
                elif status == "finished":
                    print("[FINISHED] Download complete (yt-dlp Python API).")
            ydl_opts["progress_hooks"].append(hook)
            try:
                with yt.YoutubeDL(ydl_opts) as ydl:
                    info = ydl.extract_info(url, download=True)
                    # write metadata to log
                    try:
                        with open(logfname, "a", encoding="utf-8") as lf:
                            lf.write("# METADATA\n")
                            lf.write(json.dumps(info, default=str))
                    except Exception:
                        pass
                log("Download done (Python API).")
            except Exception as e:
                log(f"yt-dlp (Python API) download failed: {e}", level="ERROR")
        else:
            # fallback to executable
            if not os.path.exists(YTDLP_PATH):
                log("yt-dlp executable not found; attempting to download it.", level="WARNING")
                if not download_yt_dlp_exe():
                    log("No yt-dlp available; cannot proceed with downloads.", level="ERROR")
                    return
            out_template = os.path.join(out_dir, "%(title)s.%(ext)s")
            args = [YTDLP_PATH, "--newline", "--no-warnings", "-o", out_template, url]
            try:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
            except Exception as e:
                log(f"Failed to launch yt-dlp.exe: {e}", level="ERROR")
                return
            # read stdout and write to log; also show progress lines
            try:
                with open(logfname, "a", encoding="utf-8") as lf:
                    for ln in proc.stdout:
                        lf.write(ln)
                        lf.flush()
                        if ln.startswith("[download]"):
                            # show progress prominently
                            print("\n" + "="*80)
                            print(ln.strip())
                            print("="*80)
                proc.wait(timeout=600)
                if proc.returncode == 0:
                    log("yt-dlp (exe) finished successfully.")
                else:
                    log(f"yt-dlp (exe) exited with code {proc.returncode}", level="WARNING")
            except Exception as e:
                log(f"Error while running yt-dlp.exe: {e}", level="ERROR")
    finally:
        # Stop sampler and save stats
        try:
            stop_event.set()
        except Exception:
            pass
        if sampler_thread is not None:
            sampler_thread.join(timeout=2)
        try:
            # write sampled stats to file (best-effort)
            nsfile = os.path.join(LOGS_DIR, f"network_stats_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
            with open(nsfile, "w", encoding="utf-8") as nf:
                json.dump(stats_list, nf, default=str)
        except Exception:
            pass

# -------- VPN connection attempt (best-effort) --------
def try_connect_vpn(vpn_name):
    if not vpn_name:
        log("No VPN name provided; skipping VPN connect attempt")
        return False
    try:
        log(f"Trying to connect to VPN '{vpn_name}' via rasdial")
        proc = subprocess.run(["rasdial", vpn_name], capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            log(f"VPN '{vpn_name}' connected successfully.")
            return True
        else:
            log(f"rasdial returned code {proc.returncode}. Output: {proc.stdout} {proc.stderr}", level="WARNING")
            return False
    except Exception as e:
        log(f"Failed to run rasdial: {e}", level="WARNING")
        return False

# -------- Main flow --------
def main():
    prepare_folder()
    log("Starting weave_setup.py")

    ok_os, plat = check_kernel_and_windows_version()
    if not ok_os:
        log("OS check failed - quitting.", level="ERROR")
        print(f"OS check failed: platform={plat}. See logs in {LOGS_DIR}")
        return

    # test write permission to WEAVE_ROOT (if not, try elevation)
    needs_admin = False
    try:
        testfile = os.path.join(WEAVE_ROOT, ".permtest")
        with open(testfile, "w", encoding="utf-8") as f:
            f.write("x")
        os.remove(testfile)
    except Exception:
        needs_admin = True

    if needs_admin and not is_admin():
        log("Administrative rights might be required to write to C:\\. Attempting elevation.")
        r = relaunch_as_admin()
        if r is None:
            log("Launched elevated process. Exiting current process.")
            return
        elif r is False:
            log("Could not elevate to admin; will continue in limited mode.", level="WARNING")

    # Make sure we have either yt-dlp module or exe; we will preferentially use the module
    module_ver = get_yt_dlp_module_version()
    if not module_ver:
        log("yt-dlp Python module not found; ensuring yt-dlp.exe is present as a fallback.", level="WARNING")
        if not os.path.exists(YTDLP_PATH):
            download_yt_dlp_exe()

    # Try VPN connect if configured
    if VPN_NAME:
        vpn_connected = try_connect_vpn(VPN_NAME)
        if not vpn_connected:
            log("VPN connection attempt failed or no VPN configured. Continuing.", level="WARNING")

    # Prompt user for URL
    print("\nEnter the URL to download (http/https):")
    url = input("URL: ").strip()
    if not validate_url(url):
        log("Invalid URL entered - quitting.", level="ERROR")
        print("Invalid URL. Exiting. See logs for details.")
        return

    # Use yt-dlp to detect platform/extractor (no domain heuristics)
    platform_name, detect_err = detect_platform_with_yt_dlp(url)
    if platform_name:
        # Ask user to confirm
        print(f"Detected platform/extractor: {platform_name}. Is that correct? [Y/n]")
        ans = input().strip().lower()
        if ans in ("n", "no"):
            platform_name = input("Okay, enter platform name to use (or leave blank): ").strip()
    else:
        log(f"Could not detect platform automatically: {detect_err}", level="WARNING")
        platform_name = input("Couldn't detect platform. Enter platform name (or leave blank): ").strip()

    log(f"User chose platform: {platform_name}")

    # Determine downloads dir
    downloads = os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")
    if not os.path.isdir(downloads):
        downloads = os.path.expanduser("~/Downloads")
    log(f"Downloads folder resolved to: {downloads}")

    # Run download
    run_yt_dlp_download(url, downloads)

    # Open downloads folder in explorer (best-effort)
    try:
        subprocess.Popen(["explorer", downloads])
    except Exception as e:
        log(f"Failed to open Downloads folder: {e}", level="WARNING")

    log("All done. Logs and executable are in the hidden folder: " + WEAVE_ROOT)
    print("Done. Check logs in the hidden folder if you need full details.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"Unhandled error in main: {e}", level="ERROR")
        raise
