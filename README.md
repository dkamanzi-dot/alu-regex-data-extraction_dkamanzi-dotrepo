# alu-regex-data-extraction_dkamanzi-dot

# ALU Regex Data Extraction

## Author

Your Name

## Description

This program reads raw text data from an input file and extracts
six types of structured data using regex patterns. It also checks
for malicious input and rejects unsafe data.

## How to Run

1. Make sure Python 3 is installed
2. Open terminal and go to the project folder
3. Run the program:

python src/main.py

## Data Types Extracted

- Hashtags
- Currency amounts (RWF)
- URLs
- Phone numbers
- Credit card numbers
- Email addresses

## ALU Email Validation

The program separately identifies three ALU email types:

- ALU Official: @alueducation.com
- ALU Alumni: @alumni.alueducation.com
- ALU SI: @si.alueducation.com

## Security

- Rejects SQL injection attempts
- Rejects XSS script attacks
- Rejects unsafe URLs like javascript:
- Masks credit card numbers in output
- Rejects malformed emails with @@ or ..

## Output

Results are saved to output/sample-output.json
