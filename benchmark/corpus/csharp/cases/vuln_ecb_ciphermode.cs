using System.Security.Cryptography;

class VulnEcb
{
    void Encrypt()
    {
        // ZS-CS-030: ECB cipher mode leaks plaintext structure.
        var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
    }
}
