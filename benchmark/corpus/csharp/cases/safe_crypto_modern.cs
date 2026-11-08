using System;
using System.Security.Cryptography;

// ZS-CS-039 and ZS-CS-040 look-alike: AES and a password KDF.
public class ModernCrypto
{
    public string HashPassword(string password, byte[] salt)
    {
        var kdf = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
        return Convert.ToBase64String(kdf.GetBytes(32));
    }

    public byte[] EncryptCard(byte[] card)
    {
        using (var aes = Aes.Create())
        {
            return aes.CreateEncryptor().TransformFinalBlock(card, 0, card.Length);
        }
    }
}
