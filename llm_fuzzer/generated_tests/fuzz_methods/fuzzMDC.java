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