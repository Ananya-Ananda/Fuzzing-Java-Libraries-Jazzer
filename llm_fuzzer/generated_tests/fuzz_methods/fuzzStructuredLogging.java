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