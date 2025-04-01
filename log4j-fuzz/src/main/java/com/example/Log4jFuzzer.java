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

public class Log4jFuzzer {
    private static final Logger logger = LogManager.getLogger(Log4jFuzzer.class);

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String input = data.consumeString(100);

        try {
            // Fuzz PatternLayout with the input
            PatternLayout layout = PatternLayout.newBuilder()
                    .withPattern(input)
                    .build();

            LogEvent event = Log4jLogEvent.newBuilder()
                    .setLoggerName("FuzzerLogger")
                    .setLevel(Level.INFO)
                    .setMessage(new SimpleMessage("Fuzzed layout test"))
                    .build();

            layout.toByteArray(event);

            // Try fuzzing some common logger usages
            logger.info("Fuzzed pattern: {}", input);
            logger.debug(input);

            // Try a dynamic log level
            String levelStr = data.consumeString(10).toUpperCase();
            Level level = Level.toLevel(levelStr, Level.INFO);
            logger.log(level, "Message at dynamic level: {}", input);

            // Try context-based logging
            ThreadContext.put("fuzzKey", input);
            logger.info("Context map with fuzzed key: {}", input);
            ThreadContext.clearAll();

        } catch (Exception e) {
            // Expected exceptions from malformed patterns or log levels
        }
    }
}
