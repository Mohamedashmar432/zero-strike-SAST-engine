public class PasswordResetService
{
    public string GenerateResetToken()
    {
        var rng = new Random(); // ZS-CS-014: weak PRNG used for a security token
        return rng.Next(100000, 999999).ToString();
    }
}
