using System.Net;

public class HttpSetup
{
    public void Configure()
    {
        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true; // ZS-CS-021: TLS validation disabled
    }
}
