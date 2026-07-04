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

    private string Sanitize(string value)
    {
        return value.Replace("<", "&lt;").Replace(">", "&gt;");
    }
}
