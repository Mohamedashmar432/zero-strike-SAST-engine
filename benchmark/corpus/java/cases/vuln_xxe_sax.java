import javax.xml.parsers.SAXParserFactory;

public class VulnXxeSax {
    // ZS-JAVA-041: SAXParserFactory with insecure defaults (XXE)
    SAXParserFactory factory() {
        return SAXParserFactory.newInstance();
    }
}
