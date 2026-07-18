using System.Security.Cryptography;

public class LegacyCipher
{
    public void Encrypt()
    {
        var des = DES.Create(); // ZS-CS-022: weak cipher DES
    }
}
