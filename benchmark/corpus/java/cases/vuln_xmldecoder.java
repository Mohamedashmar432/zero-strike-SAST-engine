import java.beans.XMLDecoder;
import java.io.InputStream;

public class VulnXmldecoder {
    Object parse(InputStream in) {
        XMLDecoder decoder = new XMLDecoder(in);
        // ZS-JAVA-030: XMLDecoder executes arbitrary method calls described in the XML
        return decoder.readObject();
    }
}
