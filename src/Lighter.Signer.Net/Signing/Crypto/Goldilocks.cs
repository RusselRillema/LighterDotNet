using System.Buffers.Binary;

namespace Lighter.Signer.Cryptography;

/// <summary>The prime field with modulus 2^64 - 2^32 + 1 used by Lighter.</summary>
internal readonly record struct Goldilocks
{
    public const ulong Modulus = 0xFFFF_FFFF_0000_0001UL;

    public Goldilocks(ulong value)
    {
        Value = value >= Modulus ? value - Modulus : value;
    }

    private Goldilocks(UInt128 value)
    {
        Value = (ulong)(value % Modulus);
    }

    public ulong Value { get; }

    public bool IsZero => Value == 0;

    public static Goldilocks Zero => new(0UL);

    public static Goldilocks One => new(1UL);

    // The Go signer converts signed inputs with a plain two's-complement cast to uint64 before
    // reduction, so -1 must map to 2^64 - 1 = 2^32 - 2 (mod p) rather than the residue p - 1.
    public static Goldilocks FromSigned(long value) => new(unchecked((ulong)value));

    public static Goldilocks FromLittleEndian(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != sizeof(ulong))
        {
            throw new ArgumentException("A Goldilocks element must contain exactly 8 bytes.", nameof(bytes));
        }

        var value = BinaryPrimitives.ReadUInt64LittleEndian(bytes);
        if (value >= Modulus)
        {
            throw new ArgumentException("The Goldilocks element is not canonical.", nameof(bytes));
        }

        return new Goldilocks(value);
    }

    public void WriteLittleEndian(Span<byte> destination)
    {
        if (destination.Length < sizeof(ulong))
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt64LittleEndian(destination, Value);
    }

    public Goldilocks Pow(ulong exponent)
    {
        var current = this;
        var result = One;
        while (exponent != 0)
        {
            if ((exponent & 1) != 0)
            {
                result *= current;
            }

            current *= current;
            exponent >>= 1;
        }

        return result;
    }

    public Goldilocks InverseOrZero() => IsZero ? Zero : Pow(Modulus - 2);

    public static Goldilocks operator +(Goldilocks left, Goldilocks right) =>
        new((UInt128)left.Value + right.Value);

    public static Goldilocks operator -(Goldilocks left, Goldilocks right) =>
        left.Value >= right.Value
            ? new Goldilocks(left.Value - right.Value)
            : new Goldilocks(Modulus - (right.Value - left.Value));

    public static Goldilocks operator *(Goldilocks left, Goldilocks right) =>
        new((UInt128)left.Value * right.Value);

    public static Goldilocks operator -(Goldilocks value) =>
        value.IsZero ? Zero : new Goldilocks(Modulus - value.Value);

    public static implicit operator Goldilocks(ulong value) => new(value);
}
