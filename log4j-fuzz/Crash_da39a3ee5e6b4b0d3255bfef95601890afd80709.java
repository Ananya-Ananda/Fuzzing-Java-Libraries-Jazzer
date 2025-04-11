import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_da39a3ee5e6b4b0d3255bfef95601890afd80709 {
    static final String base64Bytes = String.join("", "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAAIdwQAAAAIc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAABxAH4ABHEAfgAEcQB+AARxAH4ABHEAfgAEcQB+AARxAH4ABHg=");

    public static void main(String[] args) throws Throwable {
        Crash_da39a3ee5e6b4b0d3255bfef95601890afd80709.class.getClassLoader().setDefaultAssertionStatus(true);
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