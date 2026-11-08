using System;
using System.Security.Cryptography;
using System.Text;

// ZS-CS-039 and ZS-CS-040: legacy cipher and hash provider classes.
public class LegacyCrypto
{
    public string HashPassword(string password)
    {
        var md5 = new MD5CryptoServiceProvider();
        return Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
    }

    public byte[] EncryptCard(byte[] card)
    {
        using (var des = new DESCryptoServiceProvider())
        {
            return des.CreateEncryptor().TransformFinalBlock(card, 0, card.Length);
        }
    }
}
