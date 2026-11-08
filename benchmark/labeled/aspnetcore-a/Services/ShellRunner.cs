using System.Diagnostics;

namespace NotesApi.Services;

public class ShellRunner
{
    /// <summary>Runs a maintenance command. Callers in this app pass only constants.</summary>
    public string Run(string command)
    {
        var psi = new ProcessStartInfo("/bin/sh", new[] { "-c", command }) { RedirectStandardOutput = true };
        using var p = Process.Start(psi)!;
        return p.StandardOutput.ReadToEnd();
    }

    public string Uptime() => Run("uptime");
    public string DiskFree() => Run("df -h /var/data");
}
