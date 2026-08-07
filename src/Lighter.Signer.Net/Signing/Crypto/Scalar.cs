using System.Numerics;
using System.Security.Cryptography;

namespace Lighter.Signer.Cryptography;

/// <summary>A scalar modulo the prime order of the ECgFp5 group.</summary>
internal readonly record struct Scalar
{
    public static readonly BigInteger Order = BigInteger.Parse(
        "1067993516717146951041484916571792702745057740581727230159139685185762082554198619328292418486241",
        System.Globalization.CultureInfo.InvariantCulture);

    public Scalar(BigInteger value)
    {
        Value = value % Order;
        if (Value.Sign < 0)
        {
            Value += Order;
        }
    }

    public BigInteger Value { get; }

    public static Scalar Zero => new(BigInteger.Zero);

    public static Scalar FromLittleEndian(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 40)
        {
            throw new ArgumentException("An ECgFp5 scalar must contain exactly 40 bytes.", nameof(bytes));
        }

        return new Scalar(new BigInteger(bytes, isUnsigned: true, isBigEndian: false));
    }

    public static Scalar FromFp5(Fp5 value) => FromLittleEndian(value.ToLittleEndianBytes());

    public static Scalar Random()
    {
        Span<byte> bytes = stackalloc byte[40];
        try
        {
            while (true)
            {
                RandomNumberGenerator.Fill(bytes);
                bytes[^1] &= 0x7F;
                var candidate = new BigInteger(bytes, isUnsigned: true, isBigEndian: false);
                if (candidate > BigInteger.Zero && candidate < Order)
                {
                    return new Scalar(candidate);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public byte[] ToLittleEndianBytes()
    {
        var result = new byte[40];
        if (!Value.TryWriteBytes(result, out _, isUnsigned: true, isBigEndian: false))
        {
            throw new InvalidOperationException("Failed to encode ECgFp5 scalar.");
        }

        return result;
    }

    public static Scalar operator +(Scalar left, Scalar right) => new(left.Value + right.Value);

    public static Scalar operator -(Scalar left, Scalar right) => new(left.Value - right.Value);

    public static Scalar operator *(Scalar left, Scalar right) => new(left.Value * right.Value);
}
