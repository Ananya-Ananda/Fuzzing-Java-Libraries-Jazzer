#!/usr/bin/env python3
import argparse
import os
import sys
import json
from generate_test_cases import initialize_model, clean_generated_code, generate_patch_script, parse_jacoco_report, \
    generate_targeted_fuzz_methods


def main():
    parser = argparse.ArgumentParser(description='Generate targeted fuzz methods based on JaCoCo coverage')
    parser.add_argument('--jacoco-xml', required=True, help='Path to JaCoCo XML report')
    parser.add_argument('--output-dir', default='../generated_tests/fuzz_methods', help='Output directory for fuzz methods')
    parser.add_argument('--num-methods', type=int, default=5, help='Number of targeted fuzz methods to generate')
    args = parser.parse_args()

    # Check if the XML file exists
    if not os.path.exists(args.jacoco_xml):
        print(f"Error: JaCoCo XML report not found at {args.jacoco_xml}")
        sys.exit(1)

    # Parse the JaCoCo report
    print("Parsing JaCoCo coverage report...")
    coverage_data = parse_jacoco_report(args.jacoco_xml)

    # Initialize the LLM
    print("Initializing model...")
    llm = initialize_model()

    # Generate targeted fuzz methods
    print(f"Generating {args.num_methods} targeted fuzz methods...")
    methods = generate_targeted_fuzz_methods(llm, coverage_data, args.num_methods)

    # Save the targeted methods
    os.makedirs(args.output_dir, exist_ok=True)

    # Save individual methods
    targeted_dir = os.path.join(args.output_dir, "targeted")
    os.makedirs(targeted_dir, exist_ok=True)

    for method in methods:
        filename = os.path.join(targeted_dir, f"{method['method_name']}.java")
        with open(filename, 'w') as f:
            f.write(method['method_code'])

    # Create an all_targeted_methods.java file
    all_methods_file = os.path.join(targeted_dir, "all_targeted_methods.java")
    with open(all_methods_file, 'w') as f:
        for method in methods:
            f.write(f"// Targeted fuzz method for {method['target_class']}\n")
            f.write(method['method_code'])
            f.write("\n\n")

    # Create a patch script for the targeted methods
    generate_patch_script(methods, args.output_dir)

    print(f"Generated {len(methods)} targeted fuzz methods based on coverage data")
    print(f"Methods saved to {targeted_dir}")

if __name__ == "__main__":
    main()