import javax.xml.parsers.DocumentBuilderFactory;

public class VulnXxe {
    void parse() throws Exception {
        // ZS-JAVA-003: XXE — external entity/DOCTYPE processing not disabled
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder();
    }
}
