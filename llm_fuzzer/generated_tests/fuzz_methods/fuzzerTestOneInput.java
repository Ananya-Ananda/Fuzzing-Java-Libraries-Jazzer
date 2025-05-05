public static void fuzzerTestOneInput(FuzzedDataProvider data) {
         totalExecutions++;
         
         // Make sure test cases are loaded
         if (!loadedTestCases) {
             loadTestCases();
         }
    
         // Determine whether to use a predefined test case or raw data
         boolean usePredefined = !TEST_CASES.isEmpty() && 
                               data.remainingBytes() > 0 && 
                               data.consumeBoolean();
        
         String specialTestCase = null;
         if (usePredefined) {
             int index = Math.abs(data.consumeInt()) % TEST_CASES.size();
             specialTestCase = TEST_CASES.get(index);
         }
    
         try {
             // Choose which test method to run
             int testMethod = data.remainingBytes() > 0 ? 
                     Math.abs(data.consumeInt()) % 8 : 0;
            
            switch (testMethod) {
                case 0:
                    if (specialTestCase != null && specialTestCase.contains("%")) {
                        fuzzPatternLayout(data, specialTestCase);
                    } else {
                        fuzzPatternLayout(data);
                    }
                    break;
                case 1:
                    if (specialTestCase != null) {
                        fuzzLogMessages(data, specialTestCase);
                    } else {
                        fuzzLogMessages(data);
                    }
                    break;
                case 2:
                    if (specialTestCase != null && specialTestCase.contains("{")) {
                        fuzzJsonLayout(data, specialTestCase);
                    } else {
                        fuzzJsonLayout(data);
                    }
                    break;
                case 3:
                    if (specialTestCase != null && specialTestCase.contains("{")) {
                        fuzzMessagePattern(data, specialTestCase);
                    } else {
                        fuzzMessagePattern(data);
                    }
                    break;
                case 4:
                    fuzzMDC(data);
                    break;
                case 5:
                    fuzzMarkers(data);
                    break;
                case 6:
                    fuzzStructuredLogging(data);
                    break;
                case 7:
                    fuzzLoggerConfig(data);
                    fuzzFilters(data);
                    break;
            }
    
            // Generate a report after a certain time
            if (totalExecutions % 1000 == 0 && System.currentTimeMillis() - startTime > 60000) {
                generateReport();
            }
        } catch (Exception e) {
            recordCrash("Main fuzzer method", e);
        }
    }
    "