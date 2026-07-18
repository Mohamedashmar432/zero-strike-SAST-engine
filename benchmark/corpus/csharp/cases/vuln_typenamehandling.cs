using Newtonsoft.Json;

public class JsonConfig
{
    public JsonSerializerSettings Configure()
    {
        var settings = new JsonSerializerSettings();
        settings.TypeNameHandling = TypeNameHandling.All; // ZS-CS-023: polymorphic deserialization
        return settings;
    }
}
