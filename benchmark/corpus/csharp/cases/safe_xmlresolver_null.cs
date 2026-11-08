using System.Xml;

// ZS-CS-038 look-alike: the resolver is disabled.
public class XmlImporterSafe
{
    public string Import(string xml)
    {
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        return doc.DocumentElement.Name;
    }
}
