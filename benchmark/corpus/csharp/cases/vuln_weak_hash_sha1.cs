using System.Security.Cryptography;

public class ChecksumHelper
{
    public void Hash()
    {
        var sha = SHA1.Create(); // ZS-CS-029: weak hash SHA-1
    }
}
