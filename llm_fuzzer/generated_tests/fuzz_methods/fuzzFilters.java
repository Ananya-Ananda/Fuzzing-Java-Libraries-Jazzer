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