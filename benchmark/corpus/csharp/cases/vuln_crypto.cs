using System.Security.Cryptography;

public class Hasher
{
    public byte[] Hash(byte[] data)
    {
        var md5 = MD5.Create(); // ZS-CS-005: weak hash algorithm
        return md5.ComputeHash(data);
    }
}
