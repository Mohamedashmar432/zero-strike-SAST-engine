public class VulnSecret {
    void connect() {
        // ZS-JAVA-005: hardcoded credential
        String apiKey = "sk-12345";
        System.out.println(apiKey);
    }
}
