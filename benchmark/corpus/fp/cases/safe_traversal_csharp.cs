// Negative fixture for the path-traversal rule family (ZS-CS-015/026).
// Every filesystem path below is a compile-time constant. What is
// request-derived is the file *contents* — writing tainted text to a fixed
// path is not CWE-22/73.
using System.IO;

public class SafeTraversalCSharp
{
    private const string AuditLog = "/var/log/app/audit.log";

    // The headline case: constant destination, tainted contents. Before
    // ZS-CS-026 was pinned to argument 0 this reported an arbitrary file
    // write because the note is tainted, even though the target never moves.
    public void AppendAudit()
    {
        var note = Request.QueryString["note"];
        File.WriteAllText(AuditLog, note);
    }

    public string LoadBundledConfig()
    {
        return File.ReadAllText("config/app.json");
    }
}
