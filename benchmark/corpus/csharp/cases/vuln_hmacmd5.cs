using System.Security.Cryptography;

class VulnHmacMd5
{
    void Sign()
    {
        // ZS-CS-031: weak HMAC algorithm (HMACMD5).
        var hmac = HMACMD5.Create();
    }
}
