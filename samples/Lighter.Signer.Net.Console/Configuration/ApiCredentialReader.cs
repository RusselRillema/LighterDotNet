namespace Lighter.Signer.Sample.Configuration;

public static class ApiCredentialReader
{
    private static readonly string[] RequiredFields =
    [
        "Public Key",
        "Private Key",
        "Account Index",
        "L1 Address",
        "Key Index",
    ];

    public static async Task<ApiCredentials> ReadAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("The API credential file was not found.");

        Dictionary<string, string> fields = new(StringComparer.OrdinalIgnoreCase);
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using StreamReader reader = new(stream);
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            int separator = line.IndexOf(':');
            if (separator <= 0)
                throw new InvalidDataException("The API credential file has an invalid line.");

            string name = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();
            if (value.Length == 0 || !fields.TryAdd(name, value))
                throw new InvalidDataException("The API credential file has a missing or duplicate value.");
        }

        if (RequiredFields.Any(field => !fields.ContainsKey(field)))
            throw new InvalidDataException("The API credential file does not contain every required field.");

        if (!long.TryParse(fields["Account Index"], out long accountIndex) || accountIndex <= 0)
            throw new InvalidDataException("The account index is invalid.");

        if (!byte.TryParse(fields["Key Index"], out byte keyIndex) || keyIndex > 254)
            throw new InvalidDataException("The key index is invalid.");

        return new ApiCredentials(fields["Public Key"], fields["Private Key"], accountIndex, fields["L1 Address"], keyIndex);
    }
}
