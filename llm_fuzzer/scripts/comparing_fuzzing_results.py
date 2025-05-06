#!/usr/bin/env python3
"""
Compare fuzzing results between two runs to show improvements in coverage.
"""

import os
import re
import argparse
from datetime import datetime
import json
import xml.etree.ElementTree as ET

# Configuration
HOME_DIR = os.path.expanduser("~")
PROJECT_DIR = os.path.join(HOME_DIR, "Documents/UVA/Sem2/Software Analysis/Fuzzing-Java-Libraries-Jazzer")
LOG4J_FUZZ_DIR = os.path.join(PROJECT_DIR, "log4j-fuzz")

def parse_jacoco_coverage(xml_path):
    """Parse JaCoCo XML report to get coverage metrics"""
    try:
        if not os.path.exists(xml_path):
            print(f"Error: JaCoCo XML file not found at: {xml_path}")
            return None

        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Get overall coverage
        coverage_data = {
            "instruction_covered": 0,
            "instruction_missed": 0,
            "branch_covered": 0,
            "branch_missed": 0,
            "line_covered": 0,
            "line_missed": 0,
            "method_covered": 0,
            "method_missed": 0,
            "class_covered": 0,
            "class_missed": 0,
            "packages": {}
        }

        # Handle namespaces in JaCoCo XML
        ns = {'jacoco': 'http://www.jacoco.org/jacoco/1.0/report'}

        # Try with namespace first
        counters = root.findall('./jacoco:counter', ns)

        # If no counters found with namespace, try without
        if not counters:
            counters = root.findall('./counter')

        # Process overall counters
        for counter in counters:
            counter_type = counter.get('type')
            covered = int(counter.get('covered', 0))
            missed = int(counter.get('missed', 0))

            if counter_type == 'INSTRUCTION':
                coverage_data['instruction_covered'] = covered
                coverage_data['instruction_missed'] = missed
            elif counter_type == 'BRANCH':
                coverage_data['branch_covered'] = covered
                coverage_data['branch_missed'] = missed
            elif counter_type == 'LINE':
                coverage_data['line_covered'] = covered
                coverage_data['line_missed'] = missed
            elif counter_type == 'METHOD':
                coverage_data['method_covered'] = covered
                coverage_data['method_missed'] = missed
            elif counter_type == 'CLASS':
                coverage_data['class_covered'] = covered
                coverage_data['class_missed'] = missed

        # Process package-level data
        packages = root.findall('.//jacoco:package', ns) or root.findall('.//package')

        for package in packages:
            package_name = package.get('name', '').replace('/', '.')

            if not package_name.startswith('org.apache.logging.log4j'):
                continue

            package_data = {
                "instruction_covered": 0,
                "instruction_missed": 0,
                "branch_covered": 0,
                "branch_missed": 0,
                "line_covered": 0,
                "line_missed": 0,
                "method_covered": 0,
                "method_missed": 0,
                "class_covered": 0,
                "class_missed": 0,
                "classes": {}
            }

            # Get package counters
            package_counters = package.findall('./jacoco:counter', ns) or package.findall('./counter')

            for counter in package_counters:
                counter_type = counter.get('type')
                covered = int(counter.get('covered', 0))
                missed = int(counter.get('missed', 0))

                if counter_type == 'INSTRUCTION':
                    package_data['instruction_covered'] = covered
                    package_data['instruction_missed'] = missed
                elif counter_type == 'BRANCH':
                    package_data['branch_covered'] = covered
                    package_data['branch_missed'] = missed
                elif counter_type == 'LINE':
                    package_data['line_covered'] = covered
                    package_data['line_missed'] = missed
                elif counter_type == 'METHOD':
                    package_data['method_covered'] = covered
                    package_data['method_missed'] = missed
                elif counter_type == 'CLASS':
                    package_data['class_covered'] = covered
                    package_data['class_missed'] = missed

            # Get class-level data
            classes = package.findall('./jacoco:class', ns) or package.findall('./class')

            for cls in classes:
                class_name = cls.get('name', '').replace('/', '.')

                if class_name.endswith('Test'):
                    continue

                class_data = {
                    "instruction_covered": 0,
                    "instruction_missed": 0,
                    "branch_covered": 0,
                    "branch_missed": 0,
                    "line_covered": 0,
                    "line_missed": 0,
                    "method_covered": 0,
                    "method_missed": 0
                }

                # Get class counters
                class_counters = cls.findall('./jacoco:counter', ns) or cls.findall('./counter')

                for counter in class_counters:
                    counter_type = counter.get('type')
                    covered = int(counter.get('covered', 0))
                    missed = int(counter.get('missed', 0))

                    if counter_type == 'INSTRUCTION':
                        class_data['instruction_covered'] = covered
                        class_data['instruction_missed'] = missed
                    elif counter_type == 'BRANCH':
                        class_data['branch_covered'] = covered
                        class_data['branch_missed'] = missed
                    elif counter_type == 'LINE':
                        class_data['line_covered'] = covered
                        class_data['line_missed'] = missed
                    elif counter_type == 'METHOD':
                        class_data['method_covered'] = covered
                        class_data['method_missed'] = missed

                package_data['classes'][class_name] = class_data

            coverage_data['packages'][package_name] = package_data

        return coverage_data

    except Exception as e:
        print(f"Error parsing JaCoCo XML: {e}")
        return None

def parse_summary_file(file_path):
    """Parse the fuzzing summary file to extract key metrics"""
    summary_data = {
        "total_executions": 0,
        "total_crashes": 0,
        "test_cases": 0,
        "llm_methods": 0,
        "method_names": []
    }

    try:
        if not os.path.exists(file_path):
            print(f"Error: Summary file not found at: {file_path}")
            return summary_data

        with open(file_path, 'r') as f:
            content = f.read()

            # Extract executions
            exec_match = re.search(r'Total executions: Completed (\d+)', content)
            if exec_match:
                summary_data['total_executions'] = int(exec_match.group(1))

            # Extract crashes
            crash_match = re.search(r'Total crashes detected: (\d+)', content)
            if crash_match:
                summary_data['total_crashes'] = int(crash_match.group(1))

            # Extract test cases
            cases_match = re.search(r'Number of test cases: (\d+)', content)
            if cases_match:
                summary_data['test_cases'] = int(cases_match.group(1))

            # Extract LLM methods
            methods_match = re.search(r'LLM-Generated Fuzz Methods: (\d+)', content)
            if methods_match:
                summary_data['llm_methods'] = int(methods_match.group(1))

            # Extract method names
            names_match = re.search(r'Methods: (.*?)(?:\n\n|\Z)', content, re.DOTALL)
            if names_match:
                method_names = names_match.group(1).strip()
                summary_data['method_names'] = [name.strip() for name in method_names.split(',')]

        return summary_data

    except Exception as e:
        print(f"Error parsing summary file: {e}")
        return summary_data

def extract_jazzer_metrics(output_file):
    """Extract key metrics from Jazzer output file"""
    jazzer_data = {
        "coverage": 0,
        "features": 0,
        "corpus_size": 0,
        "exec_per_sec": 0
    }

    try:
        if not os.path.exists(output_file):
            print(f"Error: Jazzer output file not found at: {output_file}")
            return jazzer_data

        with open(output_file, 'r') as f:
            content = f.read()

            # Look for the DONE line which contains final metrics
            done_match = re.search(r'#\d+\s+DONE\s+cov: (\d+) ft: (\d+) corp: (\d+)/\d+b .* exec/s: (\d+)', content)
            if done_match:
                jazzer_data['coverage'] = int(done_match.group(1))
                jazzer_data['features'] = int(done_match.group(2))
                jazzer_data['corpus_size'] = int(done_match.group(3))
                jazzer_data['exec_per_sec'] = int(done_match.group(4))

        return jazzer_data

    except Exception as e:
        print(f"Error extracting Jazzer metrics: {e}")
        return jazzer_data

def calculate_coverage_percentages(coverage_data):
    """Calculate coverage percentages from raw numbers"""
    if not coverage_data:
        return None

    result = {
        "instruction_coverage": 0,
        "branch_coverage": 0,
        "line_coverage": 0,
        "method_coverage": 0,
        "class_coverage": 0
    }

    # Calculate overall percentages
    instr_total = coverage_data['instruction_covered'] + coverage_data['instruction_missed']
    if instr_total > 0:
        result['instruction_coverage'] = (coverage_data['instruction_covered'] / instr_total) * 100

    branch_total = coverage_data['branch_covered'] + coverage_data['branch_missed']
    if branch_total > 0:
        result['branch_coverage'] = (coverage_data['branch_covered'] / branch_total) * 100

    line_total = coverage_data['line_covered'] + coverage_data['line_missed']
    if line_total > 0:
        result['line_coverage'] = (coverage_data['line_covered'] / line_total) * 100

    method_total = coverage_data['method_covered'] + coverage_data['method_missed']
    if method_total > 0:
        result['method_coverage'] = (coverage_data['method_covered'] / method_total) * 100

    class_total = coverage_data['class_covered'] + coverage_data['class_missed']
    if class_total > 0:
        result['class_coverage'] = (coverage_data['class_covered'] / class_total) * 100

    return result

def find_least_covered_classes(coverage_data, limit=5):
    """Find the least covered classes to target for fuzzing"""
    if not coverage_data or 'packages' not in coverage_data:
        return []

    all_classes = []

    # Collect all classes with their method coverage
    for package_name, package_data in coverage_data['packages'].items():
        for class_name, class_data in package_data['classes'].items():
            total_methods = class_data['method_covered'] + class_data['method_missed']
            if total_methods < 3:  # Skip classes with very few methods
                continue

            if total_methods > 0:
                method_coverage = (class_data['method_covered'] / total_methods) * 100
                all_classes.append({
                    'class': f"{package_name}.{class_name}",
                    'coverage': method_coverage,
                    'covered_methods': class_data['method_covered'],
                    'total_methods': total_methods
                })

    # Sort by coverage (lowest first)
    all_classes.sort(key=lambda x: x['coverage'])

    return all_classes[:limit]

def generate_comparison_report(before_coverage, after_coverage, before_summary, after_summary,
                               before_jazzer=None, after_jazzer=None, output_file=None):
    """Generate a detailed comparison report between two fuzzing runs"""

    if not before_coverage or not after_coverage:
        print("Error: Missing coverage data for comparison")
        return

    # Calculate coverage percentages
    before_percentages = calculate_coverage_percentages(before_coverage)
    after_percentages = calculate_coverage_percentages(after_coverage)

    # Format for report
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = f"""Fuzzing Comparison Report
======================
Generated: {now}

Summary
-------
"""

    # Basic metrics comparison
    report += f"{'Metric':<25} {'Before':<15} {'After':<15} {'Change':<15}\n"
    report += f"{'-'*25} {'-'*15} {'-'*15} {'-'*15}\n"

    # Add summary metrics
    report += f"{'Total executions':<25} {before_summary['total_executions']:<15} {after_summary['total_executions']:<15} {after_summary['total_executions'] - before_summary['total_executions']:<+15}\n"
    report += f"{'Total crashes':<25} {before_summary['total_crashes']:<15} {after_summary['total_crashes']:<15} {after_summary['total_crashes'] - before_summary['total_crashes']:<+15}\n"
    report += f"{'Test cases':<25} {before_summary['test_cases']:<15} {after_summary['test_cases']:<15} {after_summary['test_cases'] - before_summary['test_cases']:<+15}\n"
    report += f"{'LLM-generated methods':<25} {before_summary['llm_methods']:<15} {after_summary['llm_methods']:<15} {after_summary['llm_methods'] - before_summary['llm_methods']:<+15}\n"

    # Add Jazzer metrics if available
    if before_jazzer and after_jazzer:
        report += f"\nJazzer Metrics\n-------------\n"
        report += f"{'Metric':<25} {'Before':<15} {'After':<15} {'Change':<15}\n"
        report += f"{'-'*25} {'-'*15} {'-'*15} {'-'*15}\n"
        report += f"{'Coverage':<25} {before_jazzer['coverage']:<15} {after_jazzer['coverage']:<15} {after_jazzer['coverage'] - before_jazzer['coverage']:<+15}\n"
        report += f"{'Features':<25} {before_jazzer['features']:<15} {after_jazzer['features']:<15} {after_jazzer['features'] - before_jazzer['features']:<+15}\n"
        report += f"{'Corpus size':<25} {before_jazzer['corpus_size']:<15} {after_jazzer['corpus_size']:<15} {after_jazzer['corpus_size'] - before_jazzer['corpus_size']:<+15}\n"
        report += f"{'Executions per second':<25} {before_jazzer['exec_per_sec']:<15} {after_jazzer['exec_per_sec']:<15} {after_jazzer['exec_per_sec'] - before_jazzer['exec_per_sec']:<+15}\n"

    # Add coverage metrics
    report += f"\nCoverage Metrics\n----------------\n"
    report += f"{'Metric':<25} {'Before (%)':<15} {'After (%)':<15} {'Change (%)':<15}\n"
    report += f"{'-'*25} {'-'*15} {'-'*15} {'-'*15}\n"

    # Format as percentages with 2 decimal places
    report += f"{'Instruction coverage':<25} {before_percentages['instruction_coverage']:.2f}%{'':<9} {after_percentages['instruction_coverage']:.2f}%{'':<9} {(after_percentages['instruction_coverage'] - before_percentages['instruction_coverage']):.2f}%{'':<9}\n"
    report += f"{'Branch coverage':<25} {before_percentages['branch_coverage']:.2f}%{'':<9} {after_percentages['branch_coverage']:.2f}%{'':<9} {(after_percentages['branch_coverage'] - before_percentages['branch_coverage']):.2f}%{'':<9}\n"
    report += f"{'Line coverage':<25} {before_percentages['line_coverage']:.2f}%{'':<9} {after_percentages['line_coverage']:.2f}%{'':<9} {(after_percentages['line_coverage'] - before_percentages['line_coverage']):.2f}%{'':<9}\n"
    report += f"{'Method coverage':<25} {before_percentages['method_coverage']:.2f}%{'':<9} {after_percentages['method_coverage']:.2f}%{'':<9} {(after_percentages['method_coverage'] - before_percentages['method_coverage']):.2f}%{'':<9}\n"
    report += f"{'Class coverage':<25} {before_percentages['class_coverage']:.2f}%{'':<9} {after_percentages['class_coverage']:.2f}%{'':<9} {(after_percentages['class_coverage'] - before_percentages['class_coverage']):.2f}%{'':<9}\n"

    # Add raw coverage numbers for reference
    report += f"\nRaw Coverage Counts\n------------------\n"
    report += f"{'Metric':<25} {'Before':<15} {'After':<15} {'Change':<15}\n"
    report += f"{'-'*25} {'-'*15} {'-'*15} {'-'*15}\n"
    report += f"{'Instructions covered':<25} {before_coverage['instruction_covered']:<15} {after_coverage['instruction_covered']:<15} {after_coverage['instruction_covered'] - before_coverage['instruction_covered']:<+15}\n"
    report += f"{'Branches covered':<25} {before_coverage['branch_covered']:<15} {after_coverage['branch_covered']:<15} {after_coverage['branch_covered'] - before_coverage['branch_covered']:<+15}\n"
    report += f"{'Lines covered':<25} {before_coverage['line_covered']:<15} {after_coverage['line_covered']:<15} {after_coverage['line_covered'] - before_coverage['line_covered']:<+15}\n"
    report += f"{'Methods covered':<25} {before_coverage['method_covered']:<15} {after_coverage['method_covered']:<15} {after_coverage['method_covered'] - before_coverage['method_covered']:<+15}\n"
    report += f"{'Classes covered':<25} {before_coverage['class_covered']:<15} {after_coverage['class_covered']:<15} {after_coverage['class_covered'] - before_coverage['class_covered']:<+15}\n"

    # List LLM-generated methods
    report += f"\nLLM-Generated Methods\n--------------------\n"

    # Compare before and after methods
    all_methods = set(before_summary['method_names'] + after_summary['method_names'])

    for method in sorted(all_methods):
        in_before = method in before_summary['method_names']
        in_after = method in after_summary['method_names']

        if in_before and in_after:
            report += f"- {method} (present in both runs)\n"
        elif in_after:
            report += f"+ {method} (added in second run)\n"
        else:
            report += f"- {method} (only in first run)\n"

    # Add analysis
    report += f"\nAnalysis\n--------\n"

    # Calculate key improvements
    method_improvement = after_percentages['method_coverage'] - before_percentages['method_coverage']
    line_improvement = after_percentages['line_coverage'] - before_percentages['line_coverage']

    if method_improvement > 0 or line_improvement > 0:
        report += f"The LLM-generated fuzz methods improved code coverage:\n"
        if method_improvement > 0:
            report += f"- Method coverage increased by {method_improvement:.2f}%\n"
        if line_improvement > 0:
            report += f"- Line coverage increased by {line_improvement:.2f}%\n"
    else:
        report += "The LLM-generated fuzz methods did not significantly improve code coverage.\n"

    # Add additional insights if available
    if after_summary['llm_methods'] > before_summary['llm_methods']:
        new_methods = after_summary['llm_methods'] - before_summary['llm_methods']
        report += f"\nAdded {new_methods} new LLM-generated fuzz methods in the second run.\n"

    # Save to file if output path provided
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"Comparison report saved to: {output_file}")
        except Exception as e:
            print(f"Error saving report: {e}")

    return report

def main():
    parser = argparse.ArgumentParser(description='Compare fuzzing results between two runs')
    parser.add_argument('--before-jacoco', required=True, help='Path to JaCoCo XML report from first run')
    parser.add_argument('--after-jacoco', required=True, help='Path to JaCoCo XML report from second run')
    parser.add_argument('--before-summary', required=True, help='Path to summary file from first run')
    parser.add_argument('--after-summary', required=True, help='Path to summary file from second run')
    parser.add_argument('--before-jazzer', help='Path to Jazzer output from first run')
    parser.add_argument('--after-jazzer', help='Path to Jazzer output from second run')
    parser.add_argument('--output', default='fuzzing_comparison.txt', help='Output file for comparison report')
    args = parser.parse_args()

    # Parse coverage data
    print("Parsing JaCoCo reports...")
    before_coverage = parse_jacoco_coverage(args.before_jacoco)
    after_coverage = parse_jacoco_coverage(args.after_jacoco)

    # Parse summary files
    print("Parsing summary files...")
    before_summary = parse_summary_file(args.before_summary)
    after_summary = parse_summary_file(args.after_summary)

    # Parse Jazzer output if available
    before_jazzer = None
    after_jazzer = None

    if args.before_jazzer and args.after_jazzer:
        print("Parsing Jazzer output...")
        before_jazzer = extract_jazzer_metrics(args.before_jazzer)
        after_jazzer = extract_jazzer_metrics(args.after_jazzer)

    # Generate comparison report
    print("Generating comparison report...")
    report = generate_comparison_report(
        before_coverage,
        after_coverage,
        before_summary,
        after_summary,
        before_jazzer,
        after_jazzer,
        args.output
    )

    print("Done!")
    return 0

if __name__ == "__main__":
    main()