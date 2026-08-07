namespace Lighter.Signer.Cryptography;

/// <summary>Poseidon2 over Goldilocks with the Plonky2 width-12 parameters used by Lighter.</summary>
internal static class Poseidon2
{
    private const int Width = 12;
    private const int Rate = 8;
    private const int HalfFullRounds = 4;

    private static readonly ulong[][] ExternalConstants =
    [
        [15_492_826_721_047_263_190, 11_728_330_187_201_910_315, 8_836_021_247_773_420_868, 16_777_404_051_263_952_451, 5_510_875_212_538_051_896, 6_173_089_941_271_892_285, 2_927_757_366_422_211_339, 10_340_958_981_325_008_808, 8_541_987_352_684_552_425, 9_739_599_543_776_434_497, 15_073_950_188_101_532_019, 12_084_856_431_752_384_512],
        [4_584_713_381_960_671_270, 8_807_052_963_476_652_830, 54_136_601_502_601_741, 4_872_702_333_905_478_703, 5_551_030_319_979_516_287, 12_889_366_755_535_460_989, 16_329_242_193_178_844_328, 412_018_088_475_211_848, 10_505_784_623_379_650_541, 9_758_812_378_619_434_837, 7_421_979_329_386_275_117, 375_240_370_024_755_551],
        [3_331_431_125_640_721_931, 15_684_937_309_956_309_981, 578_521_833_432_107_983, 14_379_242_000_670_861_838, 17_922_409_828_154_900_976, 8_153_494_278_429_192_257, 15_904_673_920_630_731_971, 11_217_863_998_460_634_216, 3_301_540_195_510_742_136, 9_937_973_023_749_922_003, 3_059_102_938_155_026_419, 1_895_288_289_490_976_132],
        [5_580_912_693_628_927_540, 10_064_804_080_494_788_323, 9_582_481_583_369_602_410, 10_186_259_561_546_797_986, 247_426_333_829_703_916, 13_193_193_905_461_376_067, 6_386_232_593_701_758_044, 17_954_717_245_501_896_472, 1_531_720_443_376_282_699, 2_455_761_864_255_501_970, 11_234_429_217_864_304_495, 4_746_959_618_548_874_102],
        [13_571_697_342_473_846_203, 17_477_857_865_056_504_753, 15_963_032_953_523_553_760, 16_033_593_225_279_635_898, 14_252_634_232_868_282_405, 8_219_748_254_835_277_737, 7_459_165_569_491_914_711, 15_855_939_513_193_752_003, 16_788_866_461_340_278_896, 7_102_224_659_693_946_577, 3_024_718_005_636_976_471, 13_695_468_978_618_890_430],
        [8_214_202_050_877_825_436, 2_670_727_992_739_346_204, 16_259_532_062_589_659_211, 11_869_922_396_257_088_411, 3_179_482_916_972_760_137, 13_525_476_046_633_427_808, 3_217_337_278_042_947_412, 14_494_689_598_654_046_340, 15_837_379_330_312_175_383, 8_029_037_639_801_151_344, 2_153_456_285_263_517_937, 8_301_106_462_311_849_241],
        [13_294_194_396_455_217_955, 17_394_768_489_610_594_315, 12_847_609_130_464_867_455, 14_015_739_446_356_528_640, 5_879_251_655_839_607_853, 9_747_000_124_977_436_185, 8_950_393_546_890_284_269, 10_765_765_936_405_694_368, 14_695_323_910_334_139_959, 16_366_254_691_123_000_864, 15_292_774_414_889_043_182, 10_910_394_433_429_313_384],
        [17_253_424_460_214_596_184, 3_442_854_447_664_030_446, 3_005_570_425_335_613_727, 10_859_158_614_900_201_063, 9_763_230_642_109_343_539, 6_647_722_546_511_515_039, 909_012_944_955_815_706, 18_101_204_076_790_399_111, 11_588_128_829_349_125_809, 15_863_878_496_612_806_566, 5_201_119_062_417_750_399, 176_665_553_780_565_743],
    ];

    private static readonly ulong[] InternalConstants =
    [
        11_921_381_764_981_422_944, 10_318_423_381_711_320_787, 8_291_411_502_347_000_766,
        229_948_027_109_387_563, 9_152_521_390_190_983_261, 7_129_306_032_690_285_515,
        15_395_989_607_365_232_011, 8_641_397_269_074_305_925, 17_256_848_792_241_043_600,
        6_046_475_228_902_245_682, 12_041_608_676_381_094_092, 12_785_542_378_683_951_657,
        14_546_032_085_337_914_034, 3_304_199_118_235_116_851, 16_499_627_707_072_547_655,
        10_386_478_025_625_759_321, 13_475_579_315_436_919_170, 16_042_710_511_297_532_028,
        1_411_266_850_385_657_080, 9_024_840_976_168_649_958, 14_047_056_970_978_379_368,
        838_728_605_080_212_101,
    ];

    private static readonly ulong[] MatrixDiagonal =
    [
        0xC3B6_C08E_23BA_9300, 0xD84B_5DE9_4A32_4FB6, 0x0D0C_371C_5B35_B84F,
        0x7964_F570_E718_8037, 0x5DAF_18BB_D996_604B, 0x6743_BC47_B959_5257,
        0x5528_B936_2C59_BB70, 0xAC45_E25B_7127_B68B, 0xA207_7D7D_FBB6_06B5,
        0xF3FA_AC6F_AEE3_78AE, 0x0C63_88B5_1545_E883, 0xD27D_BB69_4491_7B60,
    ];

    public static Fp5 HashToFp5(IReadOnlyList<Goldilocks> input)
    {
        var output = HashNToMNoPad(input, 5);
        return new Fp5(output[0], output[1], output[2], output[3], output[4]);
    }

    public static Goldilocks[] HashNToMNoPad(IReadOnlyList<Goldilocks> input, int outputCount)
    {
        if (outputCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(outputCount));
        }

        var state = new Goldilocks[Width];
        for (var offset = 0; offset < input.Count; offset += Rate)
        {
            for (var index = 0; index < Rate && offset + index < input.Count; index++)
            {
                state[index] = input[offset + index];
            }

            Permute(state);
        }

        var output = new Goldilocks[outputCount];
        var written = 0;
        while (written < outputCount)
        {
            for (var index = 0; index < Rate && written < outputCount; index++)
            {
                output[written++] = state[index];
            }

            if (written < outputCount)
            {
                Permute(state);
            }
        }

        return output;
    }

    public static void Permute(Span<Goldilocks> state)
    {
        if (state.Length != Width)
        {
            throw new ArgumentException("Poseidon2 state must contain 12 elements.", nameof(state));
        }

        ExternalLinearLayer(state);
        FullRounds(state, 0);
        PartialRounds(state);
        FullRounds(state, HalfFullRounds);
    }

    private static void FullRounds(Span<Goldilocks> state, int start)
    {
        for (var round = start; round < start + HalfFullRounds; round++)
        {
            for (var index = 0; index < Width; index++)
            {
                state[index] += new Goldilocks(ExternalConstants[round][index]);
                state[index] = SBox(state[index]);
            }

            ExternalLinearLayer(state);
        }
    }

    private static void PartialRounds(Span<Goldilocks> state)
    {
        foreach (var roundConstant in InternalConstants)
        {
            state[0] += new Goldilocks(roundConstant);
            state[0] = SBox(state[0]);
            InternalLinearLayer(state);
        }
    }

    private static Goldilocks SBox(Goldilocks value)
    {
        var square = value * value;
        var sixth = square * value;
        sixth *= sixth;
        return sixth * value;
    }

    private static void ExternalLinearLayer(Span<Goldilocks> state)
    {
        for (var offset = 0; offset < Width; offset += 4)
        {
            var t01 = state[offset] + state[offset + 1];
            var t23 = state[offset + 2] + state[offset + 3];
            var total = t01 + t23;
            var x0 = state[offset];
            var x2 = state[offset + 2];
            state[offset] = total + t01 + state[offset + 1];
            state[offset + 1] = total + state[offset + 1] + x2 + x2;
            state[offset + 2] = total + t23 + state[offset + 3];
            state[offset + 3] = total + state[offset + 3] + x0 + x0;
        }

        Span<Goldilocks> sums = stackalloc Goldilocks[4];
        for (var index = 0; index < sums.Length; index++)
        {
            sums[index] = state[index] + state[index + 4] + state[index + 8];
        }

        for (var index = 0; index < Width; index++)
        {
            state[index] += sums[index % 4];
        }
    }

    private static void InternalLinearLayer(Span<Goldilocks> state)
    {
        var sum = Goldilocks.Zero;
        for (var index = 0; index < Width; index++)
        {
            sum += state[index];
        }

        for (var index = 0; index < Width; index++)
        {
            state[index] = sum + (state[index] * new Goldilocks(MatrixDiagonal[index]));
        }
    }
}
