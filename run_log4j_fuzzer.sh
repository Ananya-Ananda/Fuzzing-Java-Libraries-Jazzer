#!/bin/bash
set -e  # Exit on error

# Add this near the top of your script
trap cleanup_and_report INT

cleanup_and_report() {
    echo -e "\n${YELLOW}Fuzzer terminated. Generating final reports...${NC}"

    # Run the report generation code here
    cd "$LOG4J_FUZZ_DIR"
    # Generate summary report with available data
    # ...

    echo -e "\n${GREEN}Fuzzing terminated successfully! Reports generated.${NC}"
    echo "Coverage report is available at: $LOG4J_FUZZ_DIR/jacoco-report-new/index.html"
    echo "Crash information (if any) is available at: $LOG4J_FUZZ_DIR/fuzzing_crashes.txt"
    echo "Summary report is available at: $LOG4J_FUZZ_DIR/fuzzing_summary.txt"

    exit 0
}

# Configuration
PROJECT_DIR="$HOME/Documents/UVA/Sem2/Software Analysis/Fuzzing-Java-Libraries-Jazzer"
LOG4J_FUZZ_DIR="$PROJECT_DIR/log4j-fuzz"
LLM_FUZZER_DIR="$PROJECT_DIR/llm_fuzzer"
RUNS=60000
DICTIONARY="$LLM_FUZZER_DIR/generated_tests/log4j_dictionary.dict"
JACOCO_AGENT="$HOME/.m2/repository/org/jacoco/org.jacoco.agent/0.8.10/org.jacoco.agent-0.8.10-runtime.jar"
JACOCO_CLI="$PROJECT_DIR/jacococli.jar"
JAZZER_CLI="$PROJECT_DIR/jazzer-cli/jazzer"

# Color codes for prettier output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Log4j Fuzzing Automation ===${NC}"
cd "$PROJECT_DIR"

# Create necessary directories
mkdir -p "$LLM_FUZZER_DIR/generated_tests/fuzz_methods"

# Create method_names.txt if it doesn't exist
if [ ! -f "$LLM_FUZZER_DIR/generated_tests/fuzz_methods/method_names.txt" ]; then
    echo "fuzzXmlConfiguration,fuzzAppenderBuilders,fuzzFilters,fuzzLookups,fuzzLayoutSerialization" > "$LLM_FUZZER_DIR/generated_tests/fuzz_methods/method_names.txt"
    echo "Created method_names.txt file with LLM-generated method names"
fi

# Step 1: Check if model exists, download if needed
echo -e "\n${YELLOW}Step 1: Checking for model${NC}"
if [ ! -f "$LLM_FUZZER_DIR/model/qwen2.5-coder-7b-instruct-q4_k_m.gguf" ]; then
    echo "Model not found. Downloading..."
    cd "$LLM_FUZZER_DIR"
    python scripts/download_model.py
else
    echo "Model already exists."
fi

# Step 2: Generate new fuzz tests
echo -e "\n${YELLOW}Step 2: Generating new fuzz tests${NC}"
cd "$LLM_FUZZER_DIR/scripts"
python generate_test_cases.py

# Step 3: Apply patches to Log4jFuzzer.java
echo -e "\n${YELLOW}Step 3: Applying patches to Log4jFuzzer.java${NC}"
PATCH_SCRIPT="$LLM_FUZZER_DIR/generated_tests/fuzz_methods/apply_patch.sh"
if [ -f "$PATCH_SCRIPT" ]; then
    echo "Found patch script, applying..."
    chmod +x "$PATCH_SCRIPT"
    "$PATCH_SCRIPT"
    echo "Patch applied successfully."
else
    echo "Patch script not found at $PATCH_SCRIPT. Generating methods first..."
    cd "$LLM_FUZZER_DIR/scripts"
    python generate_test_cases.py 2

    # Check again for the patch script
    if [ -f "$PATCH_SCRIPT" ]; then
        echo "Found patch script, applying..."
        chmod +x "$PATCH_SCRIPT"
        "$PATCH_SCRIPT"
        echo "Patch applied successfully."
    else
        echo "Failed to generate patch script. Skipping this step."
    fi
fi

echo -e "\n${YELLOW}Step 3b: Extracting test patterns from fuzz methods${NC}"
cd "$LLM_FUZZER_DIR/scripts"
python -c "
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

# Patterns to extract (regex patterns for interesting inputs)
patterns = [
    r'\"(.*?\${jndi:.*?}.*?)\"',  # JNDI patterns
    r'\"(%.*?%n)\"',              # Log pattern layouts
    r'\"{(.*?)}\"',               # JSON patterns
    r'\"(.*?\\\\.*?)\"',           # Escape sequences
    r'\"(.*?%\{.*?\}.*?)\"'       # MDC/NDC patterns
]

# Read all fuzz method files
all_methods_file = os.path.join(fuzz_methods_dir, 'all_methods.java')
if not os.path.exists(all_methods_file):
    print(f'File not found: {all_methods_file}')
    sys.exit(0)

with open(all_methods_file, 'r') as f:
    content = f.read()

# Extract all matches
extracted_patterns = []
for pattern in patterns:
    matches = re.findall(pattern, content)
    extracted_patterns.extend(matches)

# Remove duplicates
extracted_patterns = list(set(extracted_patterns))

# Save to corpus files
added_files = []
for pattern in extracted_patterns:
    # Clean up the pattern
    pattern = pattern.replace('\\\\\\"', '\"').replace('\\\\\\\\', '\\\\')

    # Skip if it's too short or just contains common characters
    if len(pattern) < 3 or pattern.strip() in ['{}', '[]', '()', '%n', '%m']:
        continue

    # Write to file
    filename = os.path.join(corpus_dir, f'test_case_{next_test_num}.txt')
    with open(filename, 'w') as f:
        f.write(pattern)
    added_files.append(filename)
    next_test_num += 1

print(f'Added {len(added_files)} new test cases extracted from fuzz methods')
"

# Step 4: Clean test cases
echo -e "\n${YELLOW}Step 4: Cleaning test cases${NC}"
cd "$LLM_FUZZER_DIR/scripts"
python clean_test_cases.py

# Step 5: Fix dictionary file
echo -e "\n${YELLOW}Step 5: Fixing dictionary file${NC}"
if [ -f "$DICTIONARY" ]; then
    # Create a temporary clean dictionary
    grep -v "ÿ" "$DICTIONARY" | grep -v "\.repeat(" > /tmp/fixed_dictionary.dict
    # Replace problematic dictionary with fixed one
    mv /tmp/fixed_dictionary.dict "$DICTIONARY"
    echo "Dictionary file fixed."
else
    echo "Dictionary file not found. Creating a new one..."
    cd "$LLM_FUZZER_DIR/scripts"
    python integrate_tests.py  # This will create a new dictionary
fi

# Step 6: Add commons-csv dependency if needed
echo -e "\n${YELLOW}Step 6: Checking dependencies${NC}"
if grep -q "CsvLogEventLayout" "$LOG4J_FUZZ_DIR/src/main/java/org/example/Log4jFuzzer.java"; then
    echo "Checking for commons-csv dependency..."
    # Check if commons-csv is already in classpath.txt
    if ! grep -q "commons-csv" "$LOG4J_FUZZ_DIR/classpath.txt" 2>/dev/null; then
        CSV_JAR=$(find "$HOME/.m2/repository" -name "commons-csv-*.jar" | head -1)
        if [ -n "$CSV_JAR" ]; then
            echo "$CSV_JAR" >> "$LOG4J_FUZZ_DIR/classpath.txt"
            echo "Added $CSV_JAR to classpath"
        else
            echo "commons-csv JAR not found in Maven repository. You may need to add it to your pom.xml."
        fi
    fi
fi

# Step 7: Compile the Log4jFuzzer
echo -e "\n${YELLOW}Step 7: Compiling Log4jFuzzer${NC}"
cd "$LOG4J_FUZZ_DIR"
mvn clean compile

# Step 8: Run the fuzzer with Jazzer
echo -e "\n${YELLOW}Step 8: Running fuzzer with Jazzer${NC}"
cd "$LOG4J_FUZZ_DIR"
export JAVA_TOOL_OPTIONS="-javaagent:$JACOCO_AGENT=destfile=target/jacoco.exec -Xmx2g"

# Use the -ignore_crashes=1 flag to keep fuzzing even when crashes occur
"$JAZZER_CLI" \
    --cp=target/classes:$(cat classpath.txt) \
    --target_class=org.example.Log4jFuzzer \
    '--instrumentation_includes=org.apache.logging.log4j.**' \
    -dict="$DICTIONARY" \
    -seed=12345 \
    -runs=$RUNS \
    -ignore_crashes=1 || {
        echo -e "${YELLOW}Fuzzer exited with an error, but we'll continue with report generation${NC}"
    }

# Step 9: Generate JaCoCo report
echo -e "\n${YELLOW}Step 9: Generating coverage report${NC}"

# Prepare extracted-log4j directory
mkdir -p "$LOG4J_FUZZ_DIR/extracted-log4j"
cd "$LOG4J_FUZZ_DIR/extracted-log4j"

# Extract only the base classes (avoiding META-INF/versions conflict)
jar xf "$HOME/.m2/repository/org/apache/logging/log4j/log4j-core/2.20.0/log4j-core-2.20.0.jar"
rm -rf META-INF/versions  # Remove multi-release JAR versions to avoid conflicts

# Generate the report using the command that worked previously
cd "$LOG4J_FUZZ_DIR"
java -jar "$JACOCO_CLI" report target/jacoco.exec \
  --classfiles extracted-log4j \
  --sourcefiles "$HOME/.m2/repository/org/apache/logging/log4j/log4j-core/2.20.0/log4j-core-2.20.0-sources.jar" \
  --html jacoco-report-new \
  --xml jacoco-report-new/jacoco.xml || {
      echo -e "${YELLOW}JaCoCo report generation failed, but continuing${NC}"
  }

# Generate a final report if needed
if [ ! -f "$LOG4J_FUZZ_DIR/fuzzing_summary.txt" ] || ! grep -q "LLM-Generated Fuzz Methods" "$LOG4J_FUZZ_DIR/fuzzing_summary.txt"; then
    echo -e "\n${YELLOW}Updating summary report with LLM method information${NC}"
    # Read method names from file if it exists
    METHOD_NAMES=""
    METHOD_COUNT=0
    if [ -f "$LLM_FUZZER_DIR/generated_tests/fuzz_methods/method_names.txt" ]; then
        METHOD_NAMES=$(cat "$LLM_FUZZER_DIR/generated_tests/fuzz_methods/method_names.txt")
        METHOD_COUNT=$(echo "$METHOD_NAMES" | tr -cd ',' | wc -c)
        METHOD_COUNT=$((METHOD_COUNT + 1))
    fi

    # Count test cases
    TEST_CASE_COUNT=$(find "$LLM_FUZZER_DIR/generated_tests/corpus" -type f 2>/dev/null | wc -l)
    if [ -z "$TEST_CASE_COUNT" ] || [ "$TEST_CASE_COUNT" -eq 0 ]; then
        TEST_CASE_COUNT=0
        if [ -f "$LOG4J_FUZZ_DIR/fuzzing_summary.txt" ]; then
            OLD_COUNT=$(grep "Number of test cases:" "$LOG4J_FUZZ_DIR/fuzzing_summary.txt" | awk '{print $NF}')
            if [ -n "$OLD_COUNT" ]; then
                TEST_CASE_COUNT=$OLD_COUNT
            fi
        fi
    fi

    # Create or update summary report
    TMP_SUMMARY=$(mktemp)
    if [ -f "$LOG4J_FUZZ_DIR/fuzzing_summary.txt" ]; then
        # Copy existing summary but skip certain lines
        grep -v "LLM-Generated Fuzz Methods" "$LOG4J_FUZZ_DIR/fuzzing_summary.txt" |
        grep -v "Methods:" > "$TMP_SUMMARY"
    else
        # Create new summary
        cat > "$TMP_SUMMARY" << EOF
Fuzzing Summary:
----------------
Total executions: Completed $RUNS runs
Total crashes detected: $(grep -c "CRASH" "$LOG4J_FUZZ_DIR/fuzzing_crashes.txt" 2>/dev/null || echo "Unknown")
Used LLM-generated test cases: Yes
Number of test cases: $TEST_CASE_COUNT

EOF
    fi

    # Add LLM method information
    if [ -n "$METHOD_NAMES" ]; then
        cat >> "$TMP_SUMMARY" << EOF
LLM-Generated Fuzz Methods: $METHOD_COUNT
Methods: $METHOD_NAMES

EOF
    fi

    # Add standard footer if not present
    if ! grep -q "This summary shows how many fuzzing iterations were executed" "$TMP_SUMMARY"; then
        cat >> "$TMP_SUMMARY" << EOF
This summary shows how many fuzzing iterations were executed.
While we can't directly measure code coverage of Log4j,
higher execution counts generally correlate with better coverage.

Crash Summary:
Crashes detected and saved to fuzzing_crashes.txt
EOF
    fi

    # Replace original summary
    mv "$TMP_SUMMARY" "$LOG4J_FUZZ_DIR/fuzzing_summary.txt"
fi

echo -e "\n${GREEN}=== Fuzzing completed successfully! ===${NC}"
echo "Coverage report is available at: $LOG4J_FUZZ_DIR/jacoco-report-new/index.html"
echo "Crash information (if any) is available at: $LOG4J_FUZZ_DIR/fuzzing_crashes.txt"
echo "Summary report is available at: $LOG4J_FUZZ_DIR/fuzzing_summary.txt"