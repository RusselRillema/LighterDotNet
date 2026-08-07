using System.Security.Cryptography;

namespace Lighter.Signer.Cryptography;

internal sealed class SchnorrSigner
{
    private readonly Scalar _privateKey;

    public SchnorrSigner(string privateKeyHex)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyHex);
        var normalized = privateKeyHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? privateKeyHex[2..]
            : privateKeyHex;

        byte[] privateKeyBytes;
        try
        {
            privateKeyBytes = Convert.FromHexString(normalized);
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The API private key is not valid hexadecimal.", nameof(privateKeyHex), exception);
        }

        try
        {
            if (privateKeyBytes.Length != 40)
            {
                throw new ArgumentException("The API private key must contain exactly 40 bytes.", nameof(privateKeyHex));
            }

            _privateKey = Scalar.FromLittleEndian(privateKeyBytes);
            if (_privateKey == Scalar.Zero)
            {
                throw new ArgumentException("The API private key cannot be zero.", nameof(privateKeyHex));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyBytes);
        }
    }

    public Fp5 PublicKey => EcPoint.Generator.Multiply(_privateKey).Encode();

    public SchnorrSignature Sign(Fp5 hashedMessage) => Sign(hashedMessage, Scalar.Random());

    internal SchnorrSignature Sign(Fp5 hashedMessage, Scalar nonce)
    {
        if (nonce == Scalar.Zero)
        {
            throw new ArgumentException("The Schnorr nonce cannot be zero.", nameof(nonce));
        }

        var encodedR = EcPoint.Generator.Multiply(nonce).Encode();
        var preimage = new Goldilocks[10];
        for (var index = 0; index < 5; index++)
        {
            preimage[index] = encodedR[index];
            preimage[index + 5] = hashedMessage[index];
        }

        var challenge = Scalar.FromFp5(Poseidon2.HashToFp5(preimage));
        return new SchnorrSignature(nonce - (challenge * _privateKey), challenge);
    }
}

internal readonly record struct SchnorrSignature(Scalar S, Scalar E)
{
    public byte[] ToBytes()
    {
        var result = new byte[80];
        S.ToLittleEndianBytes().CopyTo(result, 0);
        E.ToLittleEndianBytes().CopyTo(result, 40);
        return result;
    }
}
