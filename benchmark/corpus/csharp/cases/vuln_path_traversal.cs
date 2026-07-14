using System.IO;

public class FileViewer
{
    public string ReadFile()
    {
        var fileName = Request.QueryString["file"];
        return File.ReadAllText(fileName); // ZS-CS-015: path traversal
    }
}
