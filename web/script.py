#!/usr/bin/env python3
"""
Credit Card Pattern File Encryptor
Scans Downloads directory for files containing credit card patterns and encrypts them.
"""

import os
import re
import sys
from pathlib import Path
from cryptography.fernet import Fernet

def generate_key():
    """Generate a new encryption key."""
    return Fernet.generate_key()

def save_key(key, key_file="encryption_key.key"):
    """Save the encryption key to a file."""
    with open(key_file, "wb") as f:
        f.write(key)
    print(f"Encryption key saved to: {key_file}")

def load_key(key_file="encryption_key.key"):
    """Load the encryption key from a file."""
    try:
        with open(key_file, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Key file {key_file} not found. Generating new key...")
        key = generate_key()
        save_key(key, key_file)
        return key

def find_credit_card_patterns(text):
    """
    Find potential credit card numbers in text.
    This uses basic patterns - not foolproof but catches common formats.
    """
    # Common credit card patterns (with optional spaces/dashes)
    patterns = [
        r'\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b',  # Visa
        r'\b5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b',  # Mastercard
        r'\b3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b',  # American Express
        r'\b6011[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b',  # Discover
        r'\b[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'  # Generic 16-digit
    ]
    
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    return False

def scan_file_for_cc(file_path):
    """Scan a file for credit card patterns."""
    try:
        # Try to read file as text with error handling for binary files
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            return find_credit_card_patterns(content)
    except Exception as e:
        print(f"Could not scan {file_path}: {e}")
        return False

def encrypt_file(file_path, fernet):
    """Encrypt a file and replace it with encrypted version."""
    try:
        # Read original file
        with open(file_path, 'rb') as f:
            original_data = f.read()
        
        # Encrypt data
        encrypted_data = fernet.encrypt(original_data)
        
        # Write encrypted data back (with .encrypted extension)
        encrypted_path = str(file_path) + '.encrypted'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Remove original file
        os.remove(file_path)
        print(f"Encrypted: {file_path} -> {encrypted_path}")
        return True
        
    except Exception as e:
        print(f"Error encrypting {file_path}: {e}")
        return False

def scan_downloads_directory(downloads_path=None):
    """Scan the Downloads directory for files with credit card patterns."""
    if downloads_path is None:
        downloads_path = Path.home() / "Downloads"
    
    if not downloads_path.exists():
        print(f"Downloads directory not found: {downloads_path}")
        return []
    
    print(f"Scanning directory: {downloads_path}")
    
    # Load or generate encryption key
    key = load_key()
    fernet = Fernet(key)
    
    files_with_cc = []
    encrypted_count = 0
    
    # Scan all files in Downloads directory
    for file_path in downloads_path.rglob("*"):
        if file_path.is_file() and not file_path.name.endswith('.encrypted'):
            print(f"Scanning: {file_path.name}")
            
            if scan_file_for_cc(file_path):
                print(f"⚠️  Credit card pattern found in: {file_path}")
                files_with_cc.append(file_path)
                
                # Ask user before encrypting
                response = input(f"Encrypt {file_path.name}? (y/n): ").strip().lower()
                if response == 'y':
                    if encrypt_file(file_path, fernet):
                        encrypted_count += 1
    
    print(f"\nScan complete!")
    print(f"Files with credit card patterns: {len(files_with_cc)}")
    print(f"Files encrypted: {encrypted_count}")
    
    return files_with_cc

def decrypt_file(encrypted_file_path, fernet):
    """Decrypt a file."""
    try:
        # Read encrypted file
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt data
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Write decrypted data (remove .encrypted extension)
        original_path = str(encrypted_file_path).replace('.encrypted', '')
        with open(original_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"Decrypted: {encrypted_file_path} -> {original_path}")
        return True
        
    except Exception as e:
        print(f"Error decrypting {encrypted_file_path}: {e}")
        return False

def main():
    """Main function."""
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "decrypt":
            # Decrypt mode
            key = load_key()
            fernet = Fernet(key)
            
            downloads_path = Path.home() / "Downloads"
            encrypted_files = list(downloads_path.glob("*.encrypted"))
            
            if not encrypted_files:
                print("No encrypted files found in Downloads directory.")
                return
            
            print("Encrypted files found:")
            for i, file_path in enumerate(encrypted_files, 1):
                print(f"{i}. {file_path.name}")
            
            choice = input("Enter file number to decrypt (or 'all' for all files): ").strip()
            
            if choice.lower() == 'all':
                for file_path in encrypted_files:
                    decrypt_file(file_path, fernet)
            else:
                try:
                    index = int(choice) - 1
                    if 0 <= index < len(encrypted_files):
                        decrypt_file(encrypted_files[index], fernet)
                    else:
                        print("Invalid selection.")
                except ValueError:
                    print("Invalid input.")
        
        elif command == "help":
            print("Usage:")
            print("  python3 script.py          - Scan and encrypt files with CC patterns")
            print("  python3 script.py decrypt  - Decrypt encrypted files")
            print("  python3 script.py help     - Show this help")
        
        else:
            print(f"Unknown command: {command}")
            print("Use 'python3 script.py help' for usage information.")
    
    else:
        # Default: scan and encrypt
        scan_downloads_directory()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
