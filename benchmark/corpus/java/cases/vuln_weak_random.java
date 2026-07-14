import java.util.Random;

public class VulnWeakRandom {
    String resetToken() {
        // ZS-JAVA-015: weak PRNG — java.util.Random is not cryptographically secure
        Random random = new Random();
        return Integer.toString(random.nextInt());
    }
}
