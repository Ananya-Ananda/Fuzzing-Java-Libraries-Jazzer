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
