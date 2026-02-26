#!/usr/bin/env python3
"""
Optimized PDF Text Extractor with Blocking
Combines PyPDF2 extraction with proven pattern detection
Usage: mitmproxy -s pdf_cc_blocker_optimized.py
"""

import mitmproxy.http
from mitmproxy import ctx
import os
import re
from datetime import datetime
from io import BytesIO
import PyPDF2

class PDFCreditCardBlocker:
    def __init__(self):
        os.makedirs("pdf_protection", exist_ok=True)
        self.block_log = os.path.join("pdf_protection", "blocked.log")
        self.cc_pattern = re.compile(r'4111[-\s]?1111[-\s]?1111[-\s]?1111')
        
        print(f"\nPDF Credit Card Blocker Initialized\nBlock log: {self.block_log}\n")

    def is_pdf(self, flow):
        """Check if response is a PDF file"""
        return (
            flow.response.headers.get("content-type", "").lower() == "application/pdf" or
            flow.request.url.lower().endswith(".pdf") or
            flow.response.content.startswith(b'%PDF')
        )

    def extract_with_pypdf2(self, pdf_bytes):
        """Reliable text extraction using PyPDF2"""
        try:
            text = ""
            with BytesIO(pdf_bytes) as pdf_file:
                reader = PyPDF2.PdfReader(pdf_file)
                
                if reader.is_encrypted:
                    try:
                        if reader.decrypt(""):  # Try empty password
                            for page in reader.pages:
                                text += page.extract_text() + "\n"
                    except:
                        return ("encrypted", None)
                
                for page in reader.pages:
                    text += page.extract_text() + "\n"
            
            return ("success", text.strip())
        
        except Exception as e:
            return ("error", str(e))

    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        if not flow.response.content or not self.is_pdf(flow):
            return

        # Extract text using reliable PyPDF2
        status, text = self.extract_with_pypdf2(flow.response.content)
        
        # Prepare logging
        filename = os.path.basename(flow.request.url.split("?")[0]) or f"blocked_{datetime.now().timestamp()}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Always log the attempt
        with open(self.block_log, "a") as f:
            f.write(f"\n[PDF - {timestamp}]\nURL: {flow.request.url}\nStatus: {status}\n")

        # Block if credit card pattern found
        if status == "success" and text and self.cc_pattern.search(text):
            # Save evidence
            evidence_path = os.path.join("pdf_protection", f"{filename}.txt")
            with open(evidence_path, "w") as f:
                f.write(f"Blocked PDF containing CC pattern\nURL: {flow.request.url}\n\n{text}")
            
            # Block the download
            flow.response = mitmproxy.http.HTTPResponse.make(
                403,
                b"BLOCKED: This file contains sensitive credit card information",
                {"Content-Type": "text/plain"}
            )
            
            ctx.log.alert(f"BLOCKED PDF with CC data: {filename}")
        else:
            ctx.log.info(f"Processed PDF: {filename} ({status})")

addons = [PDFCreditCardBlocker()]
