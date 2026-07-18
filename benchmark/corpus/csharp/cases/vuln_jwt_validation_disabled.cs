using Microsoft.IdentityModel.Tokens;

public class JwtSetup
{
    public TokenValidationParameters Configure()
    {
        var parameters = new TokenValidationParameters();
        parameters.RequireSignedTokens = false; // ZS-CS-028: JWT signature validation disabled
        parameters.ValidateIssuerSigningKey = false; // ZS-CS-028: signing key never verified
        return parameters;
    }
}
