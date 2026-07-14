public class VulnMathRandom {
    String resetCode() {
        // ZS-JAVA-016: weak PRNG — Math.random() is not cryptographically secure
        double value = Math.random();
        return Double.toString(value);
    }
}
