using System;
using System.Security.Cryptography;

// Negative fixture: none of the ZS-CS rules should fire here.
public class CleanExample
{
    public void Greet(string visitorName)
    {
        var greeting = "hello, " + Sanitize(visitorName);
        Console.WriteLine(greeting);
    }

    public byte[] HashData(byte[] data)
    {
        var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
    }

    // The safe format-string idiom: the format string is a literal and the
    // attacker-controlled value is a substituted argument. ZS-CS-019 must not
    // fire here. It used to — matching "any tainted argument" made every
    // logger.info("User: {0}", name) call a finding, which produced 9 false
    // positives on a single real target. See tainted_argument_index.
    public string Format(string userSuppliedName)
    {
        return string.Format("User: {0}", userSuppliedName);
    }

    private string Sanitize(string value)
    {
        return value.Replace("<", "&lt;").Replace(">", "&gt;");
    }
}
