public class VulnPrintStackTraceEx {
    // ZS-JAVA-039: stack trace dumped to stderr instead of a logger
    void process() {
        try {
            Integer.parseInt("x");
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
