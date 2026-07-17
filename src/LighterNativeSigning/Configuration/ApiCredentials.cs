namespace LighterNativeSigning.Configuration;

public sealed record ApiCredentials(
    string PublicKey,
    string PrivateKey,
    long AccountIndex,
    string L1Address,
    byte KeyIndex);

