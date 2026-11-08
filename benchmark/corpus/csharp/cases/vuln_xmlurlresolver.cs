using System.Xml;

// ZS-CS-038: an XmlUrlResolver re-enables external entities.
public class XmlImporter
{
    public string Import(string xml)
    {
        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        doc.LoadXml(xml);
        return doc.DocumentElement.Name;
    }
}
