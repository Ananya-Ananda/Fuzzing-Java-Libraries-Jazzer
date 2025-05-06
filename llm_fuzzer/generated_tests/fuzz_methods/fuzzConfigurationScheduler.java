
    @FuzzTest
    public void fuzzConfigurationScheduler(byte[] data) {
        if (data.length < 10) return;

        FuzzedDataProvider fuzzedDataProvider = new FuzzedDataProvider(data);

        try {
            // Create a new ConfigurationScheduler
            ConfigurationScheduler scheduler = new ConfigurationScheduler();

            // Generate fuzzed data for scheduling
            String name = fuzzedDataProvider.consumeString(50);
            long initialDelay = fuzzedDataProvider.consumeLong();
            long delay = fuzzedDataProvider.consumeLong(0, 1000); // Keep delay reasonable

            // Schedule with different types of callbacks
            if (fuzzedDataProvider.consumeBoolean()) {
                // Schedule a configuration update
                scheduler.scheduleWithFixedDelay(
                    name,
                    new Runnable() {
                        @Override
                        public void run() {
                            // Do nothing in the test
                        }
                    },
                    initialDelay,
                    delay
                );
            }

            // Test stopping a scheduled task
            if (fuzzedDataProvider.consumeBoolean()) {
                scheduler.shutdown();
            }

            // Try to interrupt
            if (fuzzedDataProvider.consumeBoolean()) {
                scheduler.interrupt(name);
            }

        } catch (Exception e) {
            // Expected during fuzzing
        }
    }
