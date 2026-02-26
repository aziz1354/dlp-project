# Save as ~/test_yara.py
import os
import tempfile
import subprocess

def test_yara():
    YARA_RULES = os.path.expanduser("~/rules.yar")
    
    # Create test file with credit card number
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        tmpfile.write(b"Test file with credit card: 4111111111111111\n")
        tmpfile_path = tmpfile.name
    
    try:
        print(f"Testing YARA directly against test file at: {tmpfile_path}")
        print(f"Using YARA rules from: {YARA_RULES}")
        
        # Show file content
        with open(tmpfile_path, 'rb') as f:
            content = f.read()
            print(f"File content: {content}")
        
        # Run YARA
        result = subprocess.run(
            ["yara", "--no-follow-symlinks", YARA_RULES, tmpfile_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Show results
        print("YARA stdout:", result.stdout.decode() or "No matches")
        print("YARA stderr:", result.stderr.decode() or "No errors")
        
    finally:
        os.unlink(tmpfile_path)

if __name__ == "__main__":
    test_yara()
