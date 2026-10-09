namespace Acmebot.App.Options;

public class SimpleDnsPlusOptions
{
    public required Uri RootApiUrl { get; set; }

    public required string ApiKeyUser { get; set; }

    public required string SecretKey { get; set; }
}
