using System.Xml;

public class XmlLoader
{
    public XmlReader Configure()
    {
        var settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Parse; // ZS-CS-020: XXE via DTD processing
        return XmlReader.Create("report.xml", settings);
    }
}
