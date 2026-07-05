import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;

public class VulnDeserialization {
    Object load(InputStream in) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ZS-JAVA-002: insecure deserialization — no type allowlist
        return ois.readObject();
    }
}
