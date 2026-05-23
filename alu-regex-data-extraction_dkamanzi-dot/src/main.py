

import re
import json
import os


base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


input_path = os.path.join(base_dir, "input", "raw-text.txt")

# Read the input file
with open(input_path, "r") as f:
    text = f.read()

print("File loaded successfully")
print(f"Total characters read: {len(text)}")
