using System.IO;

public class ReportWriter
{
    public void Save()
    {
        var destination = Request.QueryString["dest"];
        File.WriteAllText(destination, "report body"); // ZS-CS-026: arbitrary file write
    }
}
