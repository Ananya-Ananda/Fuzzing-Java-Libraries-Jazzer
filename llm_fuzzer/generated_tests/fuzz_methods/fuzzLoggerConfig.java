private static void fuzzLoggerConfig(FuzzedDataProvider data) {
    try {
        // Create a logger
        Logger logger = LogManager.getLogger("FuzzerLogger");

        // Set and get logging level
        String levelStr = data.consumeString(Math.min(10, data.remainingBytes())).toUpperCase();
        Level level = Level.toLevel(levelStr, Level.INFO);
        logger.setLevel(level);
        Level currentLevel = logger.getLevel();
        if (currentLevel != level) {
            throw new Exception("Failed to set logging level");
        }

        // Set and get logger name
        String loggerName = data.consumeString(Math.min(50, data.remainingBytes()));
        logger.setName(loggerName);
        String currentLoggerName = logger.getName();
        if (!currentLoggerName.equals(loggerName)) {
            throw new Exception("Failed to set logger name");
        }

        // Test logging with different levels
        logger.trace("Trace message");
        logger.debug("Debug message");
        logger.info("Info message");
        logger.warn("Warn message");
        logger.error("Error message");

        // Test parameterized logging
        String param = data.consumeString(Math.min(100, data.remainingBytes()));
        logger.trace("Parameterized trace: {}", param);
        logger.debug("Parameterized debug: {}", param);
        logger.info("Parameterized info: {}", param);
        logger.warn("Parameterized warn: {}", param);
        logger.error("Parameterized error: {}", param);

    } catch (Exception e) {
        recordCrash("LoggerConfig fuzzing", e);
    }
}
"