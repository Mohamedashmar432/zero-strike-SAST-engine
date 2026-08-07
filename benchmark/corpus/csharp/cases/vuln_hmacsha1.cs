using System.Security.Cryptography;

class VulnHmacSha1
{
    void Sign()
    {
        // ZS-CS-032: weak HMAC algorithm (HMACSHA1).
        var hmac = HMACSHA1.Create();
    }
}
