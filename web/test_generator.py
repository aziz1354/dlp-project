#!/usr/bin/env python3
"""
Credit Card Test PDF Generator
Creates a PDF with sample credit card numbers for testing encryption scripts.
Uses fake/test credit card numbers that are commonly used for testing purposes.
"""

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from pathlib import Path
import datetime

def create_cc_test_pdf():
    """Create a PDF with sample credit card numbers in Downloads folder."""
    
    # Get Downloads directory
    downloads_path = Path.home() / "Downloads"
    pdf_filename = downloads_path / "test_credit_cards.pdf"
    
    # Create PDF
    c = canvas.Canvas(str(pdf_filename), pagesize=letter)
    width, height = letter
    
    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Sample Credit Card Information - FOR TESTING ONLY")
    
    # Subtitle
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(50, height - 100, "These are FAKE credit card numbers used for testing purposes only.")
    
    # Test credit card numbers (these are commonly used test numbers)
    test_cards = [
        ("Visa Test Card", "4111 1111 1111 1111", "123", "12/25"),
        ("Visa Test Card", "4012 8888 8888 1881", "456", "01/26"),
        ("MasterCard Test", "5555 5555 5555 4444", "789", "03/25"),
        ("MasterCard Test", "5105 1051 0510 5100", "321", "06/26"),
        ("American Express", "3782 822463 10005", "1234", "11/25"),
        ("American Express", "3714 496353 98431", "5678", "09/26"),
        ("Discover Test", "6011 1111 1111 1117", "654", "04/25"),
        ("Generic 16-digit", "1234 5678 9012 3456", "111", "08/25"),
        ("Another Test Card", "9876-5432-1098-7654", "222", "02/26"),
        ("Spaced Format", "4000 0000 0000 0002", "333", "07/25")
    ]
    
    y_position = height - 140
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "Test Credit Card Numbers:")
    y_position -= 30
    
    # Draw credit card information
    c.setFont("Helvetica", 11)
    for card_type, number, cvv, exp_date in test_cards:
        if y_position < 100:  # Start new page if needed
            c.showPage()
            y_position = height - 50
        
        c.drawString(50, y_position, f"Card Type: {card_type}")
        c.drawString(50, y_position - 15, f"Number: {number}")
        c.drawString(50, y_position - 30, f"CVV: {cvv}")
        c.drawString(50, y_position - 45, f"Exp: {exp_date}")
        
        # Draw a line separator
        c.line(50, y_position - 55, 500, y_position - 55)
        y_position -= 70
    
    # Add footer warning
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, 50, "WARNING: These are TEST numbers only. Do not use for actual transactions!")
    
    # Save PDF
    c.save()
    print(f"Test PDF created: {pdf_filename}")
    return pdf_filename

def create_text_file_with_cc():
    """Create a text file with credit card numbers for additional testing."""
    downloads_path = Path.home() / "Downloads"
    txt_filename = downloads_path / "credit_card_data.txt"
    
    with open(txt_filename, 'w') as f:
        f.write("Sample Credit Card Information - FOR TESTING ONLY\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Generated: {datetime.datetime.now()}\n\n")
        
        f.write("Credit Card Numbers (Test Data):\n")
        f.write("-" * 30 + "\n")
        f.write("Visa: 4111-1111-1111-1111\n")
        f.write("MasterCard: 5555 5555 5555 4444\n")
        f.write("AmEx: 378282246310005\n")
        f.write("Discover: 6011111111111117\n")
        f.write("Generic: 1234567890123456\n\n")
        
        f.write("Customer Data:\n")
        f.write("-" * 15 + "\n")
        f.write("John Doe - 4000 0000 0000 0002 - Exp: 12/25\n")
        f.write("Jane Smith - 5105105105105100 - Exp: 06/26\n")
        f.write("Bob Johnson - 371449635398431 - Exp: 09/25\n\n")
        
        f.write("WARNING: This is test data only!\n")
    
    print(f"Test text file created: {txt_filename}")
    return txt_filename

def create_csv_with_cc():
    """Create a CSV file with credit card data for testing."""
    downloads_path = Path.home() / "Downloads"
    csv_filename = downloads_path / "customer_payments.csv"
    
    with open(csv_filename, 'w') as f:
        f.write("Customer Name,Credit Card,Expiry,Amount\n")
        f.write("John Doe,4111-1111-1111-1111,12/25,$150.00\n")
        f.write("Jane Smith,5555 5555 5555 4444,06/26,$89.99\n")
        f.write("Bob Wilson,378282246310005,09/25,$234.50\n")
        f.write("Alice Brown,6011111111111117,04/26,$67.25\n")
        f.write("Charlie Davis,1234567890123456,11/25,$445.00\n")
    
    print(f"Test CSV file created: {csv_filename}")
    return csv_filename

def main():
    """Main function to create test files."""
    print("Creating test files with credit card patterns...")
    print("These files contain FAKE credit card numbers for testing only.\n")
    
    try:
        # Create different types of files
        pdf_file = create_cc_test_pdf()
        txt_file = create_text_file_with_cc()
        csv_file = create_csv_with_cc()
        
        print(f"\nTest files created successfully!")
        print(f"- PDF: {pdf_file}")
        print(f"- TXT: {txt_file}")
        print(f"- CSV: {csv_file}")
        print(f"\nYou can now test your encryption script on these files.")
        print(f"Run: python3 script.py")
        
    except Exception as e:
        print(f"Error creating test files: {e}")
        print("Make sure you have reportlab installed: pip3 install reportlab")

if __name__ == "__main__":
    main()
