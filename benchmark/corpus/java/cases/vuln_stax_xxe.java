import javax.xml.stream.XMLInputFactory;

public class VulnStaxXxe {
    void parse() throws Exception {
        // ZS-JAVA-009: StAX XXE — external entity/DTD processing not disabled
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.createXMLStreamReader(System.in);
    }
}
