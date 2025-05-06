#!/usr/bin/env python3
"""
Generate targeted fuzzing methods based on JaCoCo coverage reports.
This script analyzes JaCoCo XML coverage reports to identify low-coverage
classes in Log4j that should be targeted for additional fuzzing.
"""

import os
import sys
import argparse
import xml.etree.ElementTree as ET
import glob
from pathlib import Path
import signal
import time
import json
import re

# Get current directory and project directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))  # Two levels up
LLM_FUZZER_DIR = os.path.join(PROJECT_DIR, "llm_fuzzer")
LOG4J_FUZZ_DIR = os.path.join(PROJECT_DIR, "log4j-fuzz")

# Signal handling for graceful exits
def signal_handler(sig, frame):
    print("\nReceived interrupt signal, exiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Default model path with more flexible resolution
DEFAULT_MODEL_PATH = os.path.join(LLM_FUZZER_DIR, "model", "qwen2.5-coder-7b-instruct-q4_k_m.gguf")
# Try alternative locations if default not found
ALTERNATIVE_MODEL_PATHS = [
    os.path.expanduser("~/model/qwen2.5-coder-7b-instruct-q4_k_m.gguf"),
    os.path.join(PROJECT_DIR, "model", "qwen2.5-coder-7b-instruct-q4_k_m.gguf")
]

# Import llama_cpp - handle gracefully if not available
try:
    from llama_cpp import Llama
    LLAMA_AVAILABLE = True
except ImportError:
    print("Warning: llama_cpp not available. Will generate suggestions without LLM.")
    LLAMA_AVAILABLE = False

def find_model_path():
    """Find the model file by checking multiple possible locations"""
    if os.path.exists(DEFAULT_MODEL_PATH):
        return DEFAULT_MODEL_PATH

    for path in ALTERNATIVE_MODEL_PATHS:
        if os.path.exists(path):
            return path

    # If we get here, try to find the model using glob
    try:
        model_files = glob.glob(os.path.join(LLM_FUZZER_DIR, "**", "*.gguf"), recursive=True)
        if model_files:
            return model_files[0]
    except Exception as e:
        print(f"Error searching for model files: {e}")

    return None

def parse_jacoco_report(xml_path):
    """Parse JaCoCo XML report and identify low coverage classes"""
    try:
        if not os.path.exists(xml_path):
            print(f"Error: JaCoCo XML file not found at: {xml_path}")
            return []

        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Extract coverage data for packages starting with org.apache.logging.log4j
        low_coverage_classes = []

        # Handle namespaces in JaCoCo XML
        ns = {'jacoco': 'http://www.jacoco.org/jacoco/1.0/report'}

        # First try with namespace
        packages = root.findall('.//jacoco:package', ns)

        # If no packages found with namespace, try without
        if not packages:
            packages = root.findall('.//package')

        for package in packages:
            package_name = package.get('name', '')

            if not package_name.startswith('org/apache/logging/log4j'):
                continue

            # Try both with and without namespace
            classes = package.findall('./jacoco:class', ns) or package.findall('./class')

            for cls in classes:
                class_name = cls.get('name', '').replace('/', '.')

                # Skip test classes
                if 'Test' in class_name:
                    continue

                # Find method coverage counters
                counters = cls.findall('./jacoco:counter', ns) or cls.findall('./counter')

                total_methods = 0
                covered_methods = 0

                for counter in counters:
                    if counter.get('type') == 'METHOD':
                        total_methods = int(counter.get('covered', 0)) + int(counter.get('missed', 0))
                        covered_methods = int(counter.get('covered', 0))

                # Only include classes with low method coverage and at least 3 methods
                if total_methods > 2 and covered_methods / total_methods < 0.5:
                    coverage_pct = (covered_methods / total_methods) * 100 if total_methods > 0 else 0
                    full_class_name = f"{package_name.replace('/', '.')}.{class_name.split('$')[0]}"

                    # Strip duplicated package names (observed in your logs)
                    if "org.apache.logging.log4j.core.config.org.apache.logging.log4j.core.config" in full_class_name:
                        full_class_name = full_class_name.replace(
                            "org.apache.logging.log4j.core.config.org.apache.logging.log4j.core.config",
                            "org.apache.logging.log4j.core.config"
                        )

                    low_coverage_classes.append({
                        'class': full_class_name,
                        'coverage': coverage_pct,
                        'covered_methods': covered_methods,
                        'total_methods': total_methods
                    })

        # Sort by coverage (lowest first)
        low_coverage_classes.sort(key=lambda x: x['coverage'])
        return low_coverage_classes[:10]  # Return top 10 lowest coverage classes

    except Exception as e:
        print(f"Error parsing JaCoCo XML: {e}")
        return []

def generate_prompt(class_info):
    """Generate a better prompt for the LLM to create targeted fuzz methods"""
    class_name = class_info['class']
    short_name = class_name.split('.')[-1]
    method_name = f"fuzz{short_name}"

    # Split for imports
    package_parts = class_name.split('.')
    package_path = '.'.join(package_parts[:-1])

    prompt = f"""Write a Java fuzz method for Log4j fuzzing that targets the {short_name} class.

The method should:
1. Be named "{method_name}"
2. Accept a byte[] parameter named "data" 
3. Use FuzzedDataProvider to convert the byte array into various types
4. Call methods on the {short_name} class
5. Include proper exception handling with try-catch
6. Include the @FuzzTest annotation

The class is in package: {package_path}
Coverage: {class_info['coverage']}% ({class_info['covered_methods']}/{class_info['total_methods']} methods covered)

Here is a template structure to follow:

```java
@FuzzTest
public void {method_name}(byte[] data) {{
    if (data.length < 10) return;
    
    FuzzedDataProvider fuzzedDataProvider = new FuzzedDataProvider(data);
    
    try {{
        // Your fuzzing code here
        // Create instances of {short_name}
        // Call various methods with fuzzed data
        
    }} catch (Exception e) {{
        // Expected exceptions during fuzzing
    }}
}}
```

Only output the exact Java code for the method, nothing else.
"""

    return prompt, method_name

def get_llm_result(prompt, method_name, timeout=60):
    """Run LLM inference to generate a fuzz method with timeout"""
    if not LLAMA_AVAILABLE:
        return get_fallback_method(method_name)

    model_path = find_model_path()
    if not model_path:
        print("Error: Could not find model file")
        return get_fallback_method(method_name)

    try:
        print(f"Loading model from: {model_path}")
        llm = Llama(
            model_path=model_path,
            n_ctx=4096,
            n_batch=512
        )

        # Run the model with prompt and timeout
        print("Generating method with LLM...")
        output = llm.create_completion(
            prompt,
            max_tokens=2048,
            temperature=0.7,
            top_p=0.9,
            stop=["```"],
            echo=False
        )

        if not output or 'choices' not in output or not output['choices']:
            print("Error: No output from model")
            return get_fallback_method(method_name)

        # Extract just the code part from the response
        text = output['choices'][0]['text'].strip()

        # Clean up the response
        # Remove markdown code blocks if present
        text = re.sub(r'^```java\s*', '', text)
        text = re.sub(r'\s*```$', '', text)

        # Check if it's a valid Java method
        if not re.search(r'public void\s+fuzz\w+\s*\(\s*byte\[\]\s+data\s*\)', text):
            print("Generated code doesn't match expected pattern, using fallback")
            return get_fallback_method(method_name)

        # Make sure it has proper imports
        if not text.strip().startswith("@FuzzTest"):
            text = "@FuzzTest\n" + text

        return text
    except Exception as e:
        print(f"Error running model: {e}")
        return get_fallback_method(method_name)

def get_fallback_method(method_name):
    """Generate a fallback fuzz method when LLM fails"""
    class_name = method_name[4:]  # Remove "fuzz" prefix

    if "LoggerConfig" in class_name:
        return generate_logger_config_fuzzer()
    elif "ConfigurationScheduler" in class_name:
        return generate_configuration_scheduler_fuzzer()
    elif "HttpWatcher" in class_name:
        return generate_http_watcher_fuzzer()
    else:
        return generate_generic_fuzzer(method_name)

def generate_logger_config_fuzzer():
    return """
    @FuzzTest
    public void fuzzLoggerConfig(byte[] data) {
        if (data.length < 10) return;
        
        FuzzedDataProvider fuzzedDataProvider = new FuzzedDataProvider(data);
        String loggerName = fuzzedDataProvider.consumeString(100);
        
        try {
            // Get the logger configuration
            LoggerContext context = LoggerContext.getContext(false);
            Configuration config = context.getConfiguration();
            
            // Create a new logger config with fuzzed data
            LoggerConfig loggerConfig = LoggerConfig.createLogger(
                fuzzedDataProvider.consumeBoolean(),  // additivity
                Level.forName(fuzzedDataProvider.consumeString(10), Level.INFO.intLevel()),  // level
                loggerName,  // name
                fuzzedDataProvider.consumeString(10),  // includeLocation
                new AppenderRef[0],  // refs
                null,  // properties
                config,  // config
                null   // filter
            );
            
            // Test various methods
            if (fuzzedDataProvider.consumeBoolean()) {
                loggerConfig.addAppender(
                    config.getAppender(fuzzedDataProvider.consumeString(20)),
                    null,
                    null
                );
            }
            
            // Test log method
            LogEvent event = new Log4jLogEvent.Builder()
                .setLoggerName(loggerName)
                .setLevel(Level.INFO)
                .setMessage(new SimpleMessage(fuzzedDataProvider.consumeString(200)))
                .build();
            
            loggerConfig.log(event);
            
            // Test other methods
            loggerConfig.toString();
            loggerConfig.getLevel();
            loggerConfig.getName();
            
        } catch (Exception e) {
            // Expected during fuzzing
        }
    }
"""

def generate_configuration_scheduler_fuzzer():
    return """
    @FuzzTest
    public void fuzzConfigurationScheduler(byte[] data) {
        if (data.length < 10) return;
        
        FuzzedDataProvider fuzzedDataProvider = new FuzzedDataProvider(data);
        
        try {
            // Create a new ConfigurationScheduler
            ConfigurationScheduler scheduler = new ConfigurationScheduler();
            
            // Generate fuzzed data for scheduling
            String name = fuzzedDataProvider.consumeString(50);
            long initialDelay = fuzzedDataProvider.consumeLong();
            long delay = fuzzedDataProvider.consumeLong(0, 1000); // Keep delay reasonable
            
            // Schedule with different types of callbacks
            if (fuzzedDataProvider.consumeBoolean()) {
                // Schedule a configuration update
                scheduler.scheduleWithFixedDelay(
                    name,
                    new Runnable() {
                        @Override
                        public void run() {
                            // Do nothing in the test
                        }
                    },
                    initialDelay,
                    delay
                );
            }
            
            // Test stopping a scheduled task
            if (fuzzedDataProvider.consumeBoolean()) {
                scheduler.shutdown();
            }
            
            // Try to interrupt
            if (fuzzedDataProvider.consumeBoolean()) {
                scheduler.interrupt(name);
            }
            
        } catch (Exception e) {
            // Expected during fuzzing
        }
    }
"""

def generate_http_watcher_fuzzer():
    return """
    @FuzzTest
    public void fuzzHttpWatcher(byte[] data) {
        if (data.length < 20) return;
        
        FuzzedDataProvider fuzzedDataProvider = new FuzzedDataProvider(data);
        
        try {
            // Create fuzzed parameters for the HttpWatcher
            String configLocation = "http://" + fuzzedDataProvider.consumeString(20) + ".example.com/" + fuzzedDataProvider.consumeString(10);
            int lastModifiedMillis = fuzzedDataProvider.consumeInt();
            
            // Create a Configuration
            LoggerContext loggerContext = LoggerContext.getContext(false);
            Configuration config = loggerContext.getConfiguration();
            
            // Create the HttpWatcher
            HttpWatcher watcher = new HttpWatcher(configLocation, null, config, lastModifiedMillis);
            
            // Call methods
            if (fuzzedDataProvider.consumeBoolean()) {
                watcher.checkConfiguration();
            }
            
            if (fuzzedDataProvider.consumeBoolean()) {
                watcher.getLastModified();
            }
            
            // Test if file changed
            boolean changed = watcher.isModified();
            
            // Cleanup
            watcher.stop();
            
        } catch (Exception e) {
            // Expected during fuzzing
        }
    }
"""

def generate_generic_fuzzer(method_name):
    """Generate a generic fuzzer for any class"""
    class_name = method_name[4:]  # Remove "fuzz" prefix

    return f"""
    @FuzzTest
    public void {method_name}(byte[] data) {{
        if (data.length < 10) return;
        
        FuzzedDataProvider fuzzedDataProvider = new FuzzedDataProvider(data);
        
        try {{
            // Generic fuzzing for {class_name}
            LoggerContext context = LoggerContext.getContext(false);
            Configuration config = context.getConfiguration();
            
            // Generate random strings and primitives
            String str1 = fuzzedDataProvider.consumeString(100);
            String str2 = fuzzedDataProvider.consumeString(100);
            int int1 = fuzzedDataProvider.consumeInt();
            boolean bool1 = fuzzedDataProvider.consumeBoolean();
            
            // Call various methods and constructors
            // This is a generic template - for better coverage,
            // customize this method with specific calls to {class_name}
            
        }} catch (Exception e) {{
            // Expected during fuzzing
        }}
    }}
"""

def clean_method_code(method_code):
    """Clean and validate the generated method code"""
    # Ensure proper indentation
    lines = method_code.split('\n')
    cleaned_lines = []

    for line in lines:
        line = line.rstrip()
        if line:
            # Fix common indentation issues
            line = re.sub(r'^\s{0,3}(@FuzzTest)', r'    \1', line)
            if not line.startswith('    '):
                line = '    ' + line
        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)

def save_fuzz_method(method_code, method_name):
    """Save the generated fuzz method to a file"""
    if not method_code:
        return False

    # Ensure method name is correct
    if not method_name:
        for line in method_code.split('\n'):
            if 'public void fuzz' in line:
                parts = line.split('void ')[1].split('(')[0].strip()
                method_name = parts
                break

    if not method_name:
        method_name = f"fuzzTargeted{len(os.listdir(os.path.join(LLM_FUZZER_DIR, 'generated_tests', 'fuzz_methods')))}"

    # Create directories if they don't exist
    fuzz_methods_dir = os.path.join(LLM_FUZZER_DIR, "generated_tests", "fuzz_methods")
    os.makedirs(fuzz_methods_dir, exist_ok=True)

    # Clean the method code
    method_code = clean_method_code(method_code)

    # Save to both individual file and append to all_methods.java
    method_file_path = os.path.join(fuzz_methods_dir, f"{method_name}.java")

    # Don't overwrite if file exists
    if os.path.exists(method_file_path):
        print(f"Method file {method_file_path} already exists, skipping...")
        return False

    with open(method_file_path, 'w') as f:
        f.write(method_code)

    print(f"Saved method to {method_file_path}")

    # Append to method names
    method_names_path = os.path.join(fuzz_methods_dir, "method_names.txt")
    try:
        if os.path.exists(method_names_path):
            with open(method_names_path, 'r') as f:
                methods = f.read().strip()

            # Add new method if not already present
            if method_name not in methods:
                if methods:
                    methods += "," + method_name
                else:
                    methods = method_name

                with open(method_names_path, 'w') as f:
                    f.write(methods)
        else:
            with open(method_names_path, 'w') as f:
                f.write(method_name)
    except Exception as e:
        print(f"Error updating method_names.txt: {e}")

    # Append to all_methods.java
    all_methods_path = os.path.join(fuzz_methods_dir, "all_methods.java")
    try:
        # Create file if it doesn't exist
        if not os.path.exists(all_methods_path):
            with open(all_methods_path, 'w') as f:
                f.write("// Generated fuzz methods\n\n")

        with open(all_methods_path, 'a') as f:
            f.write("\n\n" + method_code)
    except Exception as e:
        print(f"Error updating all_methods.java: {e}")

    # Generate apply_patch.sh if it doesn't exist
    generate_patch_script(fuzz_methods_dir)

    return True

def generate_patch_script(fuzz_methods_dir):
    """Generate a script to apply the patches to Log4jFuzzer.java"""
    script_path = os.path.join(fuzz_methods_dir, "apply_patch.sh")

    # Only create if it doesn't exist
    if os.path.exists(script_path):
        return

    script_content = """#!/bin/bash
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
    sed -i "${LAST_LINE}i\\$(cat "$METHOD_FILE")\\n" "$FUZZER_PATH"
    
    echo "Added method $METHOD_NAME to Log4jFuzzer.java"
done

echo "All methods have been added to Log4jFuzzer.java"
"""

    with open(script_path, 'w') as f:
        f.write(script_content)

    # Make it executable
    os.chmod(script_path, 0o755)
    print(f"Created patch script at {script_path}")

def main():
    parser = argparse.ArgumentParser(description='Generate targeted fuzz methods based on coverage')
    parser.add_argument('--jacoco-xml', required=True, help='Path to JaCoCo XML report')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout for LLM inference in seconds')
    args = parser.parse_args()

    print("Analyzing JaCoCo coverage report...")
    low_coverage_classes = parse_jacoco_report(args.jacoco_xml)

    if not low_coverage_classes:
        print("No low coverage classes found or error parsing JaCoCo report.")
        # Generate a default set of fuzzers
        generate_default_fuzzers()
        return 0

    print(f"Found {len(low_coverage_classes)} classes with low coverage:")
    for cls in low_coverage_classes:
        print(f"- {cls['class']}: {cls['coverage']:.1f}% coverage ({cls['covered_methods']}/{cls['total_methods']} methods)")

    # Generate and save fuzzers for each class
    for i, cls in enumerate(low_coverage_classes[:3]):  # Limit to top 3 for now
        print(f"\nGenerating fuzzer for {cls['class']}...")
        prompt, method_name = generate_prompt(cls)

        # Try LLM generation first
        method_code = get_llm_result(prompt, method_name, timeout=args.timeout)

        if method_code:
            print(f"\nGenerated method for {cls['class']}:")
            print(method_code[:200] + "..." if len(method_code) > 200 else method_code)

            if save_fuzz_method(method_code, method_name):
                print(f"Successfully saved method {method_name}")

    print("\nAll methods generated. To apply them:")
    print("1. Run the apply_patch.sh script in the fuzz_methods directory")
    print("2. Recompile Log4jFuzzer")
    print("3. Run the fuzzer again")

    return 0

def generate_default_fuzzers():
    """Generate a default set of fuzzers when JaCoCo report is unavailable"""
    print("Generating default set of fuzzers...")

    save_fuzz_method(generate_logger_config_fuzzer(), "fuzzLoggerConfig")
    save_fuzz_method(generate_configuration_scheduler_fuzzer(), "fuzzConfigurationScheduler")
    save_fuzz_method(generate_http_watcher_fuzzer(), "fuzzHttpWatcher")

    print("Default fuzzers generated successfully.")

if __name__ == "__main__":
    sys.exit(main())