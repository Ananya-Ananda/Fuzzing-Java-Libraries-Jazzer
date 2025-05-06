import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_901b6932929f90442272071e9c1989e8a3d36ecf {
    static final String base64Bytes = String.join("", "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAAQdwQAAAAQc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAABxzcgARamF2YS5sYW5nLkJvb2xlYW7NIHKA1Zz67gIAAVoABXZhbHVleHAAc3EAfgACAAAAG3NxAH4AAjjaJSpzcQB+AAIAAAAXcQB+AAl0AABxAH4ABnEAfgAGc3EAfgAFAXNxAH4AAgAAABJ0AAFdcQB+AAtxAH4AC3EAfgALc3EAfgACAAAADHg=");

    public static void main(String[] args) throws Throwable {
        Crash_901b6932929f90442272071e9c1989e8a3d36ecf.class.getClassLoader().setDefaultAssertionStatus(true);
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