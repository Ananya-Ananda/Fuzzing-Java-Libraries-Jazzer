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