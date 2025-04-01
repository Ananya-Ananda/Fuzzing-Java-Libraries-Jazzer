import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class Crash_da39a3ee5e6b4b0d3255bfef95601890afd80709 {
    static final String base64Bytes = String.join("", "");

    public static void main(String[] args) throws Throwable {
        Crash_da39a3ee5e6b4b0d3255bfef95601890afd80709.class.getClassLoader().setDefaultAssertionStatus(true);
        try {
            Method fuzzerInitialize = com.example.Log4jFuzzer.class.getMethod("fuzzerInitialize");
            fuzzerInitialize.invoke(null);
        } catch (NoSuchMethodException ignored) {
            try {
                Method fuzzerInitialize = com.example.Log4jFuzzer.class.getMethod("fuzzerInitialize", String[].class);
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
        byte[] input = java.util.Base64.getDecoder().decode(base64Bytes);
        com.example.Log4jFuzzer.fuzzerTestOneInput(input);
    }
}