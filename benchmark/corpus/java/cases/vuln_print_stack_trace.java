public class VulnPrintStackTrace {
    // ZS-JAVA-038: stack trace dumped to stderr instead of a logger
    void process() {
        try {
            Integer.parseInt("x");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
