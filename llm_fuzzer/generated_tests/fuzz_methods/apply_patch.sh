#!/bin/bash
# Apply patches to Log4jFuzzer.java

# Find the project directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LLM_FUZZER_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
PROJECT_DIR="$(dirname "$LLM_FUZZER_DIR")"
LOG4J_FUZZ_DIR="$PROJECT_DIR/log4j-fuzz"

# Try common fuzzer file paths
FUZZER_PATHS=(
    "$LOG4J_FUZZ_DIR/src/main/java/org/example/Log4jFuzzer.java"
    "$LOG4J_FUZZ_DIR/src/main/java/com/example/Log4jFuzzer.java"
)

FUZZER_PATH=""
for path in "${FUZZER_PATHS[@]}"; do
    if [ -f "$path" ]; then
        FUZZER_PATH="$path"
        break
    fi
done

if [ -z "$FUZZER_PATH" ]; then
    echo "Error: Could not find Log4jFuzzer.java in known locations."
    echo "Searched in:"
    for path in "${FUZZER_PATHS[@]}"; do
        echo "  $path"
    done
    echo "Please specify the correct path."
    exit 1
fi

echo "Found Log4jFuzzer.java at: $FUZZER_PATH"

# Create backup
cp "$FUZZER_PATH" "$FUZZER_PATH.bak"
echo "Created backup at: $FUZZER_PATH.bak"

# Find the closing brace of the class
LAST_LINE=$(grep -n "}" "$FUZZER_PATH" | tail -1 | cut -d: -f1)

# Get all method files
METHOD_FILES=$(find "$SCRIPT_DIR" -name "*.java" ! -name "all_methods.java")

# Loop through each method file and insert before the last line
for METHOD_FILE in $METHOD_FILES; do
    METHOD_NAME=$(basename "$METHOD_FILE" .java)
    
    # Check if method already exists
    if grep -q "$METHOD_NAME" "$FUZZER_PATH"; then
        echo "Method $METHOD_NAME already exists in Log4jFuzzer.java, skipping..."
        continue
    fi
    
    # Insert method before the last line
    sed -i "${LAST_LINE}i\$(cat "$METHOD_FILE")\n" "$FUZZER_PATH"
    
    echo "Added method $METHOD_NAME to Log4jFuzzer.java"
done

echo "All methods have been added to Log4jFuzzer.java"
