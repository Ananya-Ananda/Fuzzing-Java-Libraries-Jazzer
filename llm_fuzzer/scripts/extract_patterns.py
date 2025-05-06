import os
import re
import sys

# Define directories
fuzz_methods_dir = '../generated_tests/fuzz_methods'
corpus_dir = '../generated_tests/corpus'

# Ensure output directory exists
os.makedirs(corpus_dir, exist_ok=True)

# Get the current highest test case number
existing_files = [f for f in os.listdir(corpus_dir) if f.startswith('test_case_')]
next_test_num = 0
if existing_files:
    nums = [int(re.search(r'test_case_(\d+)\.txt', f).group(1)) for f in existing_files if re.search(r'test_case_(\d+)\.txt', f)]
    if nums:
        next_test_num = max(nums) + 1

# Read all fuzz method files
all_methods_file = os.path.join(fuzz_methods_dir, 'all_methods.java')
if not os.path.exists(all_methods_file):
    print(f'File not found: {all_methods_file}')
    sys.exit(0)

with open(all_methods_file, 'r') as f:
    content = f.read()

# Simple pattern to extract all string literals
string_pattern = r'"([^"\\]*(\\.[^"\\]*)*)"'
matches = re.findall(string_pattern, content)

# Extract just the first element of each tuple
extracted_patterns = [match[0] for match in matches if match[0]]

# Remove duplicates
extracted_patterns = list(set(extracted_patterns))

# Save to corpus files
added_files = []
for pattern in extracted_patterns:
    # Skip if it's too short or just contains common characters
    if len(pattern) < 3 or pattern.strip() in ['{}', '[]', '()', '%n', '%m']:
        continue

    # Skip if it's a common Java identifier or parameter name
    if pattern in ['data', 'event', 'message', 'result', 'name', 'value', 'key', 'param']:
        continue

    # Write to file
    filename = os.path.join(corpus_dir, f'test_case_{next_test_num}.txt')
    with open(filename, 'w') as f:
        f.write(pattern)
    added_files.append(filename)
    next_test_num += 1

print(f'Added {len(added_files)} new test cases extracted from fuzz methods')
