# Save as ~/intercept_simple.py
import os
import tempfile
import subprocess
from mitmproxy import http

# Path to YARA rule file
YARA_RULES = os.path.expanduser("~/rules.yar")

def request(flow: http.HTTPFlow) -> None:
    """Remove caching headers from all requests"""
    print(f"[REQUEST] {flow.request.method} {flow.request.url}")
    
    # Remove cache-related headers
    if 'If-Modified-Since' in flow.request.headers:
        del flow.request.headers['If-Modified-Since']
    if 'If-None-Match' in flow.request.headers:
        del flow.request.headers['If-None-Match']
    if 'Cache-Control' in flow.request.headers:
        del flow.request.headers['Cache-Control']

def response(flow: http.HTTPFlow) -> None:
    """Process the response"""
    print(f"[RESPONSE] URL: {flow.request.url}")
    print(f"[RESPONSE] Host: {flow.request.host}")
    print(f"[RESPONSE] Path: {flow.request.path}")
    
    # Skip responses without content
    if not flow.response or not hasattr(flow.response, 'content') or not flow.response.content:
        print("[DEBUG] No content to analyze")
        return
    
    # Print response details
    print(f"[DEBUG] Status: {flow.response.status_code}")
    print(f"[DEBUG] Content-Type: {flow.response.headers.get('Content-Type', 'none')}")
    print(f"[DEBUG] Content-Length: {len(flow.response.content)} bytes")
    
    # Special handling for .txt files
    if ".txt" in flow.request.path.lower():
        print("[DEBUG] Detected .txt file")
        
        # Try to show content preview
        try:
            preview = flow.response.content[:100].decode('utf-8')
            print(f"[DEBUG] Content Preview: {preview}")
        except:
            pass
        
        # Save content to temp file
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write(flow.response.content)
            tmpfile_path = tmpfile.name
        
        try:
            # Direct check for credit card number
            if b"4111111111111111" in flow.response.content:
                print("[!] DETECTED Credit Card Number Directly!")
                flow.response = http.Response.make(
                    403,
                    b"Download blocked - contains credit card number.",
                    {"Content-Type": "text/plain"}
                )
                print("[!] Download BLOCKED")
                return
            
            # Run YARA scan
            print(f"[DEBUG] Running YARA scan...")
            result = subprocess.run(
                ["yara", "--no-follow-symlinks", YARA_RULES, tmpfile_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Check YARA results
            if result.stdout:
                print("[!] YARA Match Found:")
                print(result.stdout.decode())
                
                # Block the download
                flow.response = http.Response.make(
                    403,
                    b"Download blocked due to YARA rule match.",
                    {"Content-Type": "text/plain"}
                )
                print("[!] Download BLOCKED by YARA")
            else:
                print("[+] File passed YARA scan")
                
            # Show any YARA errors
            if result.stderr:
                print(f"[ERROR] YARA Error: {result.stderr.decode()}")
                
        finally:
            os.unlink(tmpfile_path)
