import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_f3d1205e2e4827adff5292efa397794a3869900c {
    static final String base64Bytes = String.join("", "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAAQdwQAAAAQc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAB1zcgARamF2YS5sYW5nLkJvb2xlYW7NIHKA1Zz67gIAAVoABXZhbHVleHAAc3EAfgACAAAAHHNxAH4AAp68np5zcQB+AAIAAAAYcQB+AAl0AABzcQB+AAUBcQB+AAtxAH4AC3NxAH4AAgAAABN0AANdXV1xAH4ABnEAfgAGcQB+AAZzcQB+AAIAAAALeA==");

    public static void main(String[] args) throws Throwable {
        Crash_f3d1205e2e4827adff5292efa397794a3869900c.class.getClassLoader().setDefaultAssertionStatus(true);
        try {
            Method fuzzerInitialize = org.example.Log4jFuzzer.class.getMethod("fuzzerInitialize");
            fuzzerInitialize.invoke(null);
        } catch (NoSuchMethodException ignored) {
            try {
                Method fuzzerInitialize = org.example.Log4jFuzzer.class.getMethod("fuzzerInitialize", String[].class);
                fuzzerInitialize.invoke(null, (Object) args);
            } catch (NoSuchMethodException ignored1) {
            } catch (IllegalAccessException | InvocationTargetException e) {
                e.printStackTrace();
                System.exit(1);
            }
        } catch (IllegalAccessException | InvocationTargetException e) {
            e.printStackTrace();
            System.exit(1);
        }
        com.code_intelligence.jazzer.api.CannedFuzzedDataProvider input = new com.code_intelligence.jazzer.api.CannedFuzzedDataProvider(base64Bytes);
        org.example.Log4jFuzzer.fuzzerTestOneInput(input);
    }
}