package org.example;

import org.apache.logging.log4j.core.layout.PatternLayout;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility to reproduce PatternLayout crashes from the fuzzing_crashes.txt file
 */
public class PatternLayoutCrashReproducer {

    static class CrashInfo {
        int crashNumber;
        String input;
        String pattern;
        String exceptionClass;
        String exceptionMessage;

        public CrashInfo(int crashNumber, String input, String exceptionClass, String exceptionMessage) {
            this.crashNumber = crashNumber;
            this.input = input;
            this.exceptionClass = exceptionClass;
            this.exceptionMessage = exceptionMessage;

            // Extract pattern if this is a PatternLayout crash
            if (input.startsWith("PatternLayout with pattern: ")) {
                this.pattern = input.substring("PatternLayout with pattern: ".length());
            } else {
                this.pattern = null;
            }
        }

        @Override
        public String toString() {
            return "Crash #" + crashNumber +
                    "\n  Input: " + input +
                    "\n  Pattern: " + pattern +
                    "\n  Exception: " + exceptionClass + ": " + exceptionMessage;
        }

        public boolean isPatternLayoutCrash() {
            return pattern != null;
        }
    }

    public static void main(String[] args) {
        String crashFilePath = "fuzzing_crashes.txt";
        if (args.length > 0) {
            crashFilePath = args[0];
        }

        try {
            List<CrashInfo> crashes = parseCrashFile(crashFilePath);
            System.out.println("Found " + crashes.size() + " crashes in the file.");

            // Filter only PatternLayout crashes
            List<CrashInfo> patternLayoutCrashes = new ArrayList<>();
            for (CrashInfo crash : crashes) {
                if (crash.isPatternLayoutCrash()) {
                    patternLayoutCrashes.add(crash);
                }
            }

            System.out.println("Found " + patternLayoutCrashes.size() + " PatternLayout crashes.");

            // Find unique crash patterns
            Set<String> uniquePatterns = new HashSet<>();
            for (CrashInfo crash : patternLayoutCrashes) {
                uniquePatterns.add(crash.pattern);
            }

            System.out.println("Found " + uniquePatterns.size() + " unique crash patterns.");

            // Reproduce each unique crash
            int reproduced = 0;
            int failed = 0;

            for (String pattern : uniquePatterns) {
                System.out.println("\nAttempting to reproduce crash with pattern: " + pattern);

                try {
                    reproducePatternLayoutCrash(pattern);
                    System.out.println("  Failed to reproduce crash - no exception was thrown");
                    failed++;
                } catch (Exception e) {
                    System.out.println("  Successfully reproduced: " + e.getClass().getName() + ": " + e.getMessage());
                    reproduced++;
                }
            }

            System.out.println("\nSummary:");
            System.out.println("  Reproduced: " + reproduced + " crashes");
            System.out.println("  Failed to reproduce: " + failed + " crashes");

        } catch (IOException e) {
            System.err.println("Error reading crash file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static List<CrashInfo> parseCrashFile(String filePath) throws IOException {
        List<CrashInfo> crashes = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            int crashNumber = 0;
            String input = null;
            String exception = null;

            while ((line = reader.readLine()) != null) {
                if (line.startsWith("=== CRASH #")) {
                    // Extract crash number
                    Pattern p = Pattern.compile("=== CRASH #(\\d+) ===");
                    Matcher m = p.matcher(line);
                    if (m.find()) {
                        crashNumber = Integer.parseInt(m.group(1));
                    }
                } else if (line.startsWith("Input: ")) {
                    input = line.substring("Input: ".length());
                } else if (line.startsWith("Exception: ")) {
                    exception = line.substring("Exception: ".length());

                    // When we have both input and exception, parse the exception and create CrashInfo
                    if (input != null && exception != null) {
                        String[] exceptionParts = exception.split(": ", 2);
                        String exceptionClass = exceptionParts[0];
                        String exceptionMessage = exceptionParts.length > 1 ? exceptionParts[1] : "";

                        crashes.add(new CrashInfo(crashNumber, input, exceptionClass, exceptionMessage));
                    }
                } else if (line.equals("============")) {
                    // Reset for next crash
                    input = null;
                    exception = null;
                }
            }
        }

        return crashes;
    }

    private static void reproducePatternLayoutCrash(String pattern) {
        // This mimics the behavior in Log4jFuzzer.fuzzPatternLayout
        PatternLayout layout = PatternLayout.newBuilder()
                .withPattern(pattern)
                .build();

        // If we get here, no exception was thrown
    }
}