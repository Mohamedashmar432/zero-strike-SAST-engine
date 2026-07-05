using System.Diagnostics;

public class Runner
{
    public void Run()
    {
        var cmd = Request.QueryString["cmd"];
        Process.Start(cmd); // ZS-CS-001: command injection
    }
}
