import re
import os
import json

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
input_path = os.path.join(base_dir, "input", "raw-text.txt")

with open(input_path, "r") as f:
    text = f.read()

print("File loaded successfully")

def is_malicious(line):
    bad_patterns = [
        "OR 1=1", "DROP TABLE", "SELECT *",
        "DELETE FROM", "--", "<script",
        "onerror=", "alert(", "document.cookie",
        "javascript:", "file:///"
    ]
    for pattern in bad_patterns:
        if pattern.lower() in line.lower():
            return True
    return False

# hashtags
hashtag_pattern = r"#[a-zA-Z][a-zA-Z0-9_]*"
hashtags = re.findall(hashtag_pattern, text)
print("\n--- Hashtags ---")
for tag in hashtags:
    print(tag)

# currency
currency_pattern = r"RWF\s?[\d,]+"
currencies = re.findall(currency_pattern, text)
print("\n--- Currency Amounts ---")
for amount in currencies:
    print(amount)

# urls
url_pattern = r"https?://[^\s\"'<>]+"
all_urls = re.findall(url_pattern, text)
valid_urls = []
rejected_urls = []
for url in all_urls:
    if is_malicious(url):
        rejected_urls.append(url)
    else:
        valid_urls.append(url)
print("\n--- Valid URLs ---")
for url in valid_urls:
    print(url)
print("\n--- Rejected URLs ---")
for url in rejected_urls:
    print(url)

# phone numbers

# phone numbers
phone_pattern = r"\+\d{1,3}[\s\-]?\(?\d[\d\s\-\)]{6,14}"
all_phones = re.findall(phone_pattern, text)
valid_phones = []
rejected_phones = []
for phone in all_phones:
    # clean up any newlines or dashes picked up at the end
    phone = phone.strip().split("\n")[0].strip()
    digits_only = re.sub(r"\D", "", phone)
    if set(digits_only) == {"0"}:
        rejected_phones.append(phone)
    elif 7 <= len(digits_only) <= 15:
        valid_phones.append(phone)
    else:
        rejected_phones.append(phone)
print("\n--- Valid Phone Numbers ---")
for phone in valid_phones:
    print(phone)
print("\n--- Rejected Phone Numbers ---")
for phone in rejected_phones:
    print(phone)

# credit cards
card_pattern = r"\d{4}[\s\-]?\d{4,6}[\s\-]?\d{4,6}[\s\-]?\d{0,4}"
all_cards = re.findall(card_pattern, text)
valid_cards = []
rejected_cards = []
for card in all_cards:
    digits_only = re.sub(r"\D", "", card)
    if len(digits_only) not in (15, 16):
        rejected_cards.append(card.strip())
    elif len(set(digits_only)) == 1:
        rejected_cards.append(card.strip())
    else:
        masked = "**** **** **** " + digits_only[-4:]
        valid_cards.append(masked)
print("\n--- Valid Credit Cards (Masked) ---")
for card in valid_cards:
    print(card)
print("\n--- Rejected Credit Cards ---")
for card in rejected_cards:
    print(card)

# emails
email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
all_emails = list(set(re.findall(email_pattern, text)))
valid_emails = []
rejected_emails = []
alu_official = []
alu_alumni = []
alu_si = []
for email in all_emails:
    if "@@" in email:
        rejected_emails.append(email)
    elif ".." in email:
        rejected_emails.append(email)
    elif len(email) > 254:
        rejected_emails.append(email)
    else:
        valid_emails.append(email)
        if email.endswith("@si.alueducation.com"):
            alu_si.append(email)
        elif email.endswith("@alumni.alueducation.com"):
            alu_alumni.append(email)
        elif email.endswith("@alueducation.com"):
            alu_official.append(email)
print("\n--- Valid Emails ---")
for email in valid_emails:
    print(email)
print("\n--- ALU Official ---")
for email in alu_official:
    print(email)
print("\n--- ALU Alumni ---")
for email in alu_alumni:
    print(email)
print("\n--- ALU SI ---")
for email in alu_si:
    print(email)
print("\n--- Rejected Emails ---")
for email in rejected_emails:
    print(email)

# save to json
results = {
    "hashtags": hashtags,
    "currency_amounts": currencies,
    "urls": {
        "valid": valid_urls,
        "rejected": rejected_urls
    },
    "phone_numbers": {
        "valid": valid_phones,
        "rejected": rejected_phones
    },
    "credit_cards": {
        "valid": valid_cards,
        "rejected": rejected_cards
    },
    "emails": {
        "valid": valid_emails,
        "alu_official": alu_official,
        "alu_alumni": alu_alumni,
        "alu_si": alu_si,
        "rejected": rejected_emails
    }
}

output_path = os.path.join(base_dir, "output", "sample-output.json")
with open(output_path, "w") as f:
    json.dump(results, f, indent=2)

print("\n--- Done ---")
print(f"Results saved to {output_path}")