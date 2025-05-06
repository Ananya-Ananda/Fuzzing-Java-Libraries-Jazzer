
    @FuzzTest
    public void fuzzHttpWatcher(byte[] data) {
        if (data.length < 20) return;

        FuzzedDataProvider fuzzedDataProvider = new FuzzedDataProvider(data);

        try {
            // Create fuzzed parameters for the HttpWatcher
            String configLocation = "http://" + fuzzedDataProvider.consumeString(20) + ".example.com/" + fuzzedDataProvider.consumeString(10);
            int lastModifiedMillis = fuzzedDataProvider.consumeInt();

            // Create a Configuration
            LoggerContext loggerContext = LoggerContext.getContext(false);
            Configuration config = loggerContext.getConfiguration();

            // Create the HttpWatcher
            HttpWatcher watcher = new HttpWatcher(configLocation, null, config, lastModifiedMillis);

            // Call methods
            if (fuzzedDataProvider.consumeBoolean()) {
                watcher.checkConfiguration();
            }

            if (fuzzedDataProvider.consumeBoolean()) {
                watcher.getLastModified();
            }

            // Test if file changed
            boolean changed = watcher.isModified();

            // Cleanup
            watcher.stop();

        } catch (Exception e) {
            // Expected during fuzzing
        }
    }
