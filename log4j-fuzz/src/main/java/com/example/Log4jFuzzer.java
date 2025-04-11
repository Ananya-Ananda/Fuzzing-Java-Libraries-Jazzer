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
import java.io.FileWriter;
import java.io.IOException;

public class Log4jFuzzer {
    private static final Logger logger = LogManager.getLogger(Log4jFuzzer.class);
    private static long startTime = System.currentTimeMillis();
    private static long totalExecutions = 0;
    private static int crashCount = 0;

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down fuzzer, generating final report...");
            generateReport();
        }));
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        totalExecutions++;

        try {
            // 1. Fuzz PatternLayout
            fuzzPatternLayout(data);

            // 2. Fuzz Log Messages
            fuzzLogMessages(data);

            // 3. Fuzz JSON Layout
            fuzzJsonLayout(data);

            // 4. Fuzz Message Pattern
            fuzzMessagePattern(data);

            // Generate a report after a certain time
            if (totalExecutions % 1000 == 0 && System.currentTimeMillis() - startTime > 60000) {
                generateReport();
            }
        } catch (Exception e) {
            recordCrash("Main fuzzer method", e);
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
