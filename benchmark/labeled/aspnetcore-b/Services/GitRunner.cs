using System.Diagnostics;

namespace TicketDesk.Services;

public static class GitRunner
{
    /// <summary>Runs a git subcommand. The two callers in Program.cs pass literals only.</summary>
    public static string Run(string subcommand)
    {
        var psi = new ProcessStartInfo("git") { RedirectStandardOutput = true };
        psi.ArgumentList.Add(subcommand);
        psi.ArgumentList.Add("--oneline");
        using var p = Process.Start(psi)!;
        return p.StandardOutput.ReadToEnd();
    }
}
