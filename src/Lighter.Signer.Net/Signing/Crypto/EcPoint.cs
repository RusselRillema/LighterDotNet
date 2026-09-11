using System.Numerics;

namespace Lighter.Signer.Cryptography;

/// <summary>A point on Lighter's prime-order ECgFp5 group in fractional coordinates.</summary>
internal readonly record struct EcPoint(Fp5 X, Fp5 Z, Fp5 U, Fp5 T)
{
    private static readonly Fp5 B = new(0, 263, 0, 0, 0);
    private static readonly Fp5 DoubleB = new(0, 526, 0, 0, 0);
    private static readonly Fp5 QuadrupleB = new(0, 1_052, 0, 0, 0);

    public static EcPoint Neutral => new(Fp5.Zero, Fp5.One, Fp5.Zero, Fp5.One);

    public static EcPoint Generator => new(
        new Fp5(
            12_883_135_586_176_881_569UL,
            4_356_519_642_755_055_268UL,
            5_248_930_565_894_896_907UL,
            2_165_973_894_480_315_022UL,
            2_448_410_071_095_648_785UL),
        Fp5.One,
        Fp5.One,
        new Fp5(4, 0, 0, 0, 0));

    public Fp5 Encode() => T * U.InverseOrZero();

    public EcPoint Add(EcPoint other)
    {
        Fp5 t1 = X * other.X;
        Fp5 t2 = Z * other.Z;
        Fp5 t3 = U * other.U;
        Fp5 t4 = T * other.T;
        Fp5 t5 = ((X + Z) * (other.X + other.Z)) - t1 - t2;
        Fp5 t6 = ((U + T) * (other.U + other.T)) - t3 - t4;
        Fp5 t7 = t1 + (t2 * B);
        Fp5 t8 = t4 * t7;
        Fp5 t9 = t3 * ((t5 * DoubleB) + t7 + t7);
        Fp5 t10 = (t4 + t3 + t3) * (t5 + t7);
        return new EcPoint(
            (t10 - t8) * B,
            t8 - t9,
            t6 * ((t2 * B) - t1),
            t8 + t9);
    }

    public EcPoint Double()
    {
        Fp5 t1 = Z * T;
        Fp5 t2 = t1 * T;
        Fp5 x1 = t2.Square();
        Fp5 z1 = t1 * U;
        Fp5 t3 = U.Square();
        Fp5 w1 = t2 - (t3 * (X + Z + X + Z));
        Fp5 t4 = z1.Square();
        return new EcPoint(
            t4 * QuadrupleB,
            w1.Square(),
            (w1 + z1).Square() - t4 - w1.Square(),
            x1 + x1 - (t4 * new Fp5(4, 0, 0, 0, 0)) - w1.Square());
    }

    public EcPoint Multiply(Scalar scalar)
    {
        EcPoint result = Neutral;
        EcPoint addend = this;
        BigInteger remaining = scalar.Value;
        while (remaining > 0)
        {
            if (!remaining.IsEven)
                result = result.Add(addend);

            addend = addend.Double();
            remaining >>= 1;
        }

        return result;
    }
}
