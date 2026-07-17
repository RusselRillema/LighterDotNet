namespace LighterNativeSigning.Signing.Crypto;

/// <summary>Quintic extension of the Goldilocks field, reduced by X^5 - 3.</summary>
public readonly record struct Fp5(
    Goldilocks C0,
    Goldilocks C1,
    Goldilocks C2,
    Goldilocks C3,
    Goldilocks C4)
{
    private static readonly Goldilocks W = new(3);
    private static readonly Goldilocks DthRoot = new(1_041_288_259_238_279_555UL);

    public static Fp5 Zero => new(0, 0, 0, 0, 0);

    public static Fp5 One => new(1, 0, 0, 0, 0);

    public static Fp5 Two => new(2, 0, 0, 0, 0);

    public Goldilocks this[int index] => index switch
    {
        0 => C0,
        1 => C1,
        2 => C2,
        3 => C3,
        4 => C4,
        _ => throw new ArgumentOutOfRangeException(nameof(index)),
    };

    public bool IsZero => C0.IsZero && C1.IsZero && C2.IsZero && C3.IsZero && C4.IsZero;

    public byte[] ToLittleEndianBytes()
    {
        var result = new byte[40];
        for (var index = 0; index < 5; index++)
        {
            this[index].WriteLittleEndian(result.AsSpan(index * 8, 8));
        }

        return result;
    }

    public Fp5 Square()
    {
        var doubleW = W + W;
        var c0 = (C0 * C0) + (doubleW * ((C1 * C4) + (C2 * C3)));
        var doubleC0 = C0 + C0;
        var c1 = (doubleC0 * C1) + (doubleW * C2 * C4) + (W * C3 * C3);
        var c2 = (doubleC0 * C2) + (C1 * C1) + (doubleW * C4 * C3);
        var doubleC1 = C1 + C1;
        var c3 = (doubleC0 * C3) + (doubleC1 * C2) + (W * C4 * C4);
        var c4 = (doubleC0 * C4) + (doubleC1 * C3) + (C2 * C2);
        return new Fp5(c0, c1, c2, c3, c4);
    }

    public Fp5 InverseOrZero()
    {
        if (IsZero)
        {
            return Zero;
        }

        var d = Frobenius();
        var e = d * d.Frobenius();
        var f = e * e.RepeatedFrobenius(2);
        var scalar = (C0 * f.C0) + W * ((C1 * f.C4) + (C2 * f.C3) + (C3 * f.C2) + (C4 * f.C1));
        return f * scalar.InverseOrZero();
    }

    public Fp5 Frobenius() => RepeatedFrobenius(1);

    public Fp5 RepeatedFrobenius(int count)
    {
        count %= 5;
        if (count == 0)
        {
            return this;
        }

        var root = DthRoot;
        for (var index = 1; index < count; index++)
        {
            root *= DthRoot;
        }

        var power = Goldilocks.One;
        var result = new Goldilocks[5];
        for (var index = 0; index < result.Length; index++)
        {
            result[index] = this[index] * power;
            power *= root;
        }

        return new Fp5(result[0], result[1], result[2], result[3], result[4]);
    }

    public static Fp5 operator +(Fp5 left, Fp5 right) => new(
        left.C0 + right.C0,
        left.C1 + right.C1,
        left.C2 + right.C2,
        left.C3 + right.C3,
        left.C4 + right.C4);

    public static Fp5 operator -(Fp5 left, Fp5 right) => new(
        left.C0 - right.C0,
        left.C1 - right.C1,
        left.C2 - right.C2,
        left.C3 - right.C3,
        left.C4 - right.C4);

    public static Fp5 operator -(Fp5 value) => new(-value.C0, -value.C1, -value.C2, -value.C3, -value.C4);

    public static Fp5 operator *(Fp5 a, Fp5 b)
    {
        var c0 = (a.C0 * b.C0) + W * ((a.C1 * b.C4) + (a.C2 * b.C3) + (a.C3 * b.C2) + (a.C4 * b.C1));
        var c1 = (a.C0 * b.C1) + (a.C1 * b.C0) + W * ((a.C2 * b.C4) + (a.C3 * b.C3) + (a.C4 * b.C2));
        var c2 = (a.C0 * b.C2) + (a.C1 * b.C1) + (a.C2 * b.C0) + W * ((a.C3 * b.C4) + (a.C4 * b.C3));
        var c3 = (a.C0 * b.C3) + (a.C1 * b.C2) + (a.C2 * b.C1) + (a.C3 * b.C0) + W * (a.C4 * b.C4);
        var c4 = (a.C0 * b.C4) + (a.C1 * b.C3) + (a.C2 * b.C2) + (a.C3 * b.C1) + (a.C4 * b.C0);
        return new Fp5(c0, c1, c2, c3, c4);
    }

    public static Fp5 operator *(Fp5 value, Goldilocks scalar) => new(
        value.C0 * scalar,
        value.C1 * scalar,
        value.C2 * scalar,
        value.C3 * scalar,
        value.C4 * scalar);

    public static Fp5 operator /(Fp5 numerator, Fp5 denominator)
    {
        var inverse = denominator.InverseOrZero();
        if (inverse.IsZero)
        {
            throw new DivideByZeroException();
        }

        return numerator * inverse;
    }
}

