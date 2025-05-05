private static void fuzzMDC(FuzzedDataProvider data) {
    String key = "";
    String value = "";
    try {
        if (data.remainingBytes() > 0) {
            key = data.consumeString(Math.min(50, data.remainingBytes()));
        }
        
        if (data.remainingBytes() > 0) {
            value = data.consumeString(Math.min(100, data.remainingBytes()));
        }

        MDC.put(key, value);
        logger.info("MDC with key: {} and value: {}", key, value);

        // Test clearing the MDC
        ThreadContext.clearMap();
    } catch (Exception e) {
        recordCrash("MDC fuzzing", e);
    }
}
"

private static void fuzzMarkers(FuzzedDataProvider data) {
    try {
        // Create a Marker with a name from the fuzzer input
        String markerName = data.consumeString(100);
        Marker marker = MarkerManager.getMarker(markerName);

        // Log messages with and without the marker
        logger.info(marker, "Message with marker: {}", markerName);
        logger.info("Message without marker: {}", markerName);

        // Create nested markers
        String nestedMarkerName = data.consumeString(100);
        Marker nestedMarker = MarkerManager.getMarker(nestedMarkerName).add(marker);
        logger.info(nestedMarker, "Nested message with markers: {} and {}", markerName, nestedMarkerName);

        // Test marker removal
        logger.info("Message before removing marker: {}", markerName);
        marker.remove();
        logger.info("Message after removing marker: {}", markerName);
    } catch (Exception e) {
        recordCrash("Markers fuzzing", e);
    }
}
"

private static void fuzzStructuredLogging(FuzzedDataProvider data) {
    try {
        // Create a structured log message using MapMessage
        String key = data.consumeString(10);
        String value = data.consumeString(20);
        MapMessage mapMessage = new MapMessage();
        mapMessage.put(key, value);

        // Log the map message at different levels
        logger.trace("Trace level: {}", mapMessage);
        logger.debug("Debug level: {}", mapMessage);
        logger.info("Info level: {}", mapMessage);
        logger.warn("Warn level: {}", mapMessage);
        logger.error("Error level: {}", mapMessage);

        // Test with other structured message types
        JSONLayout jsonLayout = JSONLayout.newBuilder().build();
        String jsonLogEvent = jsonLayout.toSerializable(mapMessage).toString();
        // System.out.println(jsonLogEvent); // Output the JSON log event

    } catch (Exception e) {
        recordCrash("StructuredLogging fuzzing", e);
    }
}
"

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

private static void fuzzFilters(FuzzedDataProvider data) {
    try {
        // Create a logger context
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration config = ctx.getConfiguration();
        
        // Add ThresholdFilter to the root logger
        Filter thresholdFilter = ThresholdFilter.createThresholdFilter(Level.toLevel(data.consumeString(10).toUpperCase()), null, Filter.Result.NEUTRAL);
        AppenderRef appenderRef = AppenderRef.createAppenderRef("Console", Filter.Result.ACCEPT, null);
        LoggerConfig rootLoggerConfig = config.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
        rootLoggerConfig.addFilter(thresholdFilter);
        rootLoggerConfig.addAppender(appenderRef, Filter.Result.NONE, null);

        // Create a LevelMatchFilter
        String levelStr = data.consumeString(10).toUpperCase();
        Level level = Level.toLevel(levelStr, Level.INFO);
        Filter levelMatchFilter = LevelMatchFilter.createLevelMatchFilter(level, Filter.Result.ACCEPT, Filter.Result.NEUTRAL);
        loggerConfig.addFilter(levelMatchFilter);

        // Log messages with varying levels
        logger.debug("Debug message");
        logger.info("Info message");
        logger.warn("Warn message");
        logger.error("Error message");

    } catch (Exception e) {
        recordCrash("Filters fuzzing", e);
    }
}
"

