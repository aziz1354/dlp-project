import os
import tempfile
import subprocess
from mitmproxy import http

# Path to YARA rule file (not compiled)
YARA_RULES = os.path.expanduser("~/rules.yar")

# Domains to skip interception (safe sites like search engines)
EXCLUDE_DOMAINS = {
    "google.com",
    "duckduckgo.com",
    "bing.com",
    "mozilla.org",
}

def is_file_download(flow: http.HTTPFlow) -> bool:
    """Check if response looks like a downloadable file"""
    content_type = flow.response.headers.get("Content-Type", "").lower()
    content_disp = flow.response.headers.get("Content-Disposition", "").lower()

    if "attachment" in content_disp:
        return True
    if "application/" in content_type and not ("html" in content_type or "json" in content_type):
        return True
    if any(ext in flow.request.path.lower() for ext in [".exe", ".zip", ".dll", ".bat", ".pdf", ".txt"]):
        return True
    return False

def request(flow: http.HTTPFlow) -> None:
    # Remove conditional request headers to prevent 304 responses
    if 'If-Modified-Since' in flow.request.headers:
        del flow.request.headers['If-Modified-Since']
    if 'If-None-Match' in flow.request.headers:
        del flow.request.headers['If-None-Match']
    
    print(f"[DEBUG] Processed request: {flow.request.url}")

def response(flow: http.HTTPFlow) -> None:
    # --- DEBUG: Show every request URL ---
    print(f"[DEBUG] Request URL: {flow.request.url}")

    # --- DEBUG: Show host being accessed ---
    print(f"[DEBUG] Host: {flow.request.host}")

    # Skip interception for known safe domains
    if any(domain in flow.request.host for domain in EXCLUDE_DOMAINS):
        print("[DEBUG] Skipping domain (in exclude list)")
        return

    # Only process file-like responses
    if flow.response and flow.response.content:
        
        # --- DEBUG: Content-Type and Content-Disposition ---
        content_type = flow.response.headers.get('Content-Type', '')
        content_disp = flow.response.headers.get('Content-Disposition', '')
        print(f"[DEBUG] Content-Type: {content_type}")
        print(f"[DEBUG] Content-Disposition: {content_disp}")
        print(f"[DEBUG] Response status: {flow.response.status_code}")
        print(f"[DEBUG] Response size: {len(flow.response.content)} bytes")
        
        # Show content preview for text files
        if 'text/' in content_type and len(flow.response.content) > 0:
            try:
                preview = flow.response.content[:100].decode('utf-8')
                print(f"[DEBUG] Content preview: {preview}")
            except:
                pass

        if is_file_download(flow):
            print(f"[+] Intercepted download: {flow.request.url}")

            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
                tmpfile.write(flow.response.content)
                tmpfile_path = tmpfile.name
            
            print(f"[DEBUG] Saved to temp file: {tmpfile_path}")

            try:
                # Run YARA scan directly on .yar file
                result = subprocess.run(
                    ["yara", "--no-follow-symlinks", YARA_RULES, tmpfile_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

                # --- DEBUG: Show raw YARA output ---
                if result.stdout:
                    print("[DEBUG] YARA Output:\n" + result.stdout.decode())
                if result.stderr:
                    print("[DEBUG] YARA Error:\n" + result.stderr.decode())

                if result.stdout:
                    print("[!] Match found by YARA:")
                    print(result.stdout.decode())
                    # Block the download
                    flow.response = http.Response.make(
                        403,
                        b"Download blocked due to suspicious content.",
                        {"Content-Type": "text/plain"}
                    )
                    print("[+] Download blocked!")
                else:
                    print("[+] File passed YARA scan")
            finally:
                os.unlink(tmpfile_path)  # Clean up temp file
