#!/usr/bin/env python3
"""
mitmproxy script to detect PDF files in HTTP traffic
Usage: mitmproxy -s pdf_detector.py
"""

import mitmproxy.http
from mitmproxy import ctx
import os
from datetime import datetime

class PDFDetector:
    def __init__(self):
        self.pdf_count = 0
        # Create logs directory if it doesn't exist
        os.makedirs("pdf_logs", exist_ok=True)
        
    def response(self, flow: mitmproxy.http.HTTPFlow) -> None:
        """
        This method is called for every response that passes through the proxy
        """
        # Check if the response contains PDF content
        content_type = flow.response.headers.get("content-type", "")
        
        if "application/pdf" in content_type.lower():
            # PDF detected!
            self.pdf_count += 1
            
            # Get the URL and filename from the URL path
            url = flow.request.url
            filename = url.split("/")[-1]
            if not filename.lower().endswith(".pdf"):
                filename = f"unknown_pdf_{self.pdf_count}.pdf"
                
            # Log the PDF detection
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"[{timestamp}] PDF detected: {url} (size: {len(flow.response.content)} bytes)"
            
            # Print to console
            ctx.log.info(log_message)
            
            # Save to log file
            with open("pdf_logs/pdf_detections.log", "a") as f:
                f.write(log_message + "\n")
                
            # Optionally save the PDF content
            with open(f"pdf_logs/{filename}", "wb") as f:
                f.write(flow.response.content)
                
            # Print summary
            ctx.log.alert(f"PDF #{self.pdf_count} saved to pdf_logs/{filename}")

# Add the PDFDetector instance to the addons list
addons = [PDFDetector()]
