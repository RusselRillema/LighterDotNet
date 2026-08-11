using System.Numerics;
using System.Net;
using System.Text;
using System.Text.Json;
using Lighter.Signer.Sample.Api;
using Lighter.Signer.Sample.Workflow;
using Lighter.Signer.Sample.Configuration;
using Lighter.Signer;
using Lighter.Signer.Cryptography;
using Lighter.Signer.Transactions;

var tests = new (string Name, Func<Task> Run)[]
{
    ("Poseidon2 matches official vector", TestPoseidon2Async),
    ("Schnorr matches official deterministic vector", TestSchnorrAsync),
    ("Transaction hashes match official Go signer", TestTransactionHashesAsync),
    ("Sub-account transfer matches official Go signer", TestTransferHashAsync),
    ("Create order defaults 28-day expiry", TestDefaultOrderExpiryAsync),
    ("Modify order hash matches official Go signer", TestModifyOrderHashAsync),
    ("Update leverage hash matches official Go signer", TestUpdateLeverageHashAsync),
    ("Approve integrator hash matches official Go signer", TestApproveIntegratorHashAsync),
    ("Attribute aggregation matches official Go signer", TestAttributeAggregationAsync),
    ("Market order hash matches official Go signer", TestMarketOrderHashAsync),
    ("Nil-valued attributes preserve base hash", TestNilAttributesPreserveHashAsync),
    ("Attribute validation rejects invalid combinations", TestAttributeValidationAsync),
    ("Order validation enforces per-type rules", TestOrderValidationAsync),
    ("Enum factory equals byte construction", TestEnumFactoryAsync),
    ("Custom transaction expiry honored", TestTransactionExpiryAsync),
    ("Negative and spot-market inputs match official Go signer", TestNegativeAndSpotInputHashesAsync),
    ("Package exposes only signer API types", TestPublicSurfaceAsync),
    ("REST client uses official wire contract", TestRestWireContractAsync),
    ("REST client surfaces exchange rejection", TestRestFailureAsync),
    ("Seven-step workflow state machine passes", TestSevenGoalStepsAsync),
};

foreach (var test in tests)
{
    try
    {
        await test.Run();
        Console.WriteLine($"PASS: {test.Name}");
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"FAIL: {test.Name}: {exception.Message}");
        return 1;
    }
}

return 0;

static Task TestPoseidon2Async()
{
    var fieldInputs = new ulong[] { 0, 1, 2, Goldilocks.Modulus - 1, ulong.MaxValue, 15_492_826_721_047_263_190 };
    foreach (var left in fieldInputs)
    {
        foreach (var right in fieldInputs)
        {
            var expectedProduct = (ulong)((new BigInteger(left) * right) % Goldilocks.Modulus);
            var actualProduct = (new Goldilocks(left) * new Goldilocks(right)).Value;
            AssertEqual(expectedProduct, actualProduct, "Goldilocks multiplication");
            var expectedSum = (ulong)((new BigInteger(left) + right) % Goldilocks.Modulus);
            var actualSum = (new Goldilocks(left) + new Goldilocks(right)).Value;
            AssertEqual(expectedSum, actualSum, "Goldilocks addition");
        }
    }

    var state = new Goldilocks[]
    {
        5_417_613_058_500_526_590, 2_481_548_824_842_427_254, 6_473_243_198_879_784_792,
        1_720_313_757_066_167_274, 2_806_320_291_675_974_571, 7_407_976_414_706_455_446,
        1_105_257_841_424_046_885, 7_613_435_757_403_328_049, 3_376_066_686_066_811_538,
        5_888_575_799_323_675_710, 6_689_309_723_188_675_948, 2_468_250_420_241_012_720,
    };
    var expected = new ulong[]
    {
        5_364_184_781_011_389_007, 15_309_475_861_242_939_136, 5_983_386_513_087_443_499,
        886_942_118_604_446_276, 14_903_657_885_227_062_600, 7_742_650_891_575_941_298,
        1_962_182_278_500_985_790, 10_213_480_816_595_178_755, 3_510_799_061_817_443_836,
        4_610_029_967_627_506_430, 7_566_382_334_276_534_836, 2_288_460_879_362_380_348,
    };

    Poseidon2.Permute(state);
    AssertSequenceEqual(expected, state.Select(item => item.Value), "Poseidon2 permutation");
    return Task.CompletedTask;
}

static Task TestSchnorrAsync()
{
    var privateKey = ScalarFromLimbs(
        12_235_002_942_052_073_545, 1_175_977_464_658_719_998, 8_536_934_969_147_463_310,
        6_524_687_619_313_720_391, 2_922_072_024_880_609_112);
    var nonce = ScalarFromLimbs(
        5_245_666_847_777_449_560, 15_178_169_970_799_106_939, 4_403_065_012_435_293_749,
        15_306_540_389_399_388_999, 8_935_555_081_913_173_844);
    var hashedMessage = new Fp5(
        8_398_652_514_106_806_347, 11_069_112_711_939_986_896, 9_732_488_227_085_561_369,
        18_076_754_337_204_438_535, 17_155_407_358_725_346_236);
    var expectedS = ScalarFromLimbs(
        6_950_590_877_883_398_434, 17_178_336_263_794_770_543, 11_012_823_478_139_181_320,
        16_445_091_359_523_510_936, 5_882_925_226_143_600_273);
    var expectedE = ScalarFromLimbs(
        4_544_744_459_434_870_309, 4_180_764_085_957_612_004, 3_024_669_018_778_978_615,
        15_433_417_688_859_446_606, 6_775_027_260_348_937_828);

    var signer = new SchnorrSigner(Convert.ToHexString(privateKey.ToLittleEndianBytes()));
    var signature = signer.Sign(hashedMessage, nonce);
    AssertEqual(expectedS, signature.S, "Schnorr S");
    AssertEqual(expectedE, signature.E, "Schnorr E");
    return Task.CompletedTask;
}

static Task TestTransactionHashesAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var createClock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_433));
    var createSigner = new LighterSigner(privateKey, 1, 0, 304, createClock);
    var create = createSigner.SignCreateOrder(
        new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999),
        42);
    AssertEqual(
        "aa8f0203aa47fd2f9c82b85d96a3228b40884ebf2bd7cc6e21668f0a7e5ba16e2b6f3214af822fa6",
        create.TransactionHash,
        "create-order hash");
    using (var payload = JsonDocument.Parse(create.TransactionInfo))
    {
        AssertEqual(10L, payload.RootElement.GetProperty("BaseAmount").GetInt64(), "create payload amount");
        AssertEqual(JsonValueKind.Null, payload.RootElement.GetProperty("L2TxAttributes").ValueKind, "attributes encoding");
        AssertEqual(80, Convert.FromBase64String(payload.RootElement.GetProperty("Sig").GetString()!).Length, "signature length");
    }

    var cancelClock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_434));
    var cancelSigner = new LighterSigner(privateKey, 1, 0, 304, cancelClock);
    var cancel = cancelSigner.SignCancelOrder(7, 281_474_976_710_700, 43);
    AssertEqual(
        "8a64d7b716470b2b9cc4e754d77a672d0b6e8ec88b8680c16843a166593a737a4b72ca78387f0ff6",
        cancel.TransactionHash,
        "cancel-order hash");
    return Task.CompletedTask;
}

static Task TestTransferHashAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_435));
    var signer = new LighterSigner(privateKey, 1, 0, 304, clock);
    var memo = new byte[32];
    Encoding.ASCII.GetBytes("official-transfer-vector").CopyTo(memo, 0);
    var transfer = signer.SignTransfer(
        new TransferRequest(2, 1, 0, 1, 4_294_967_299, 17, memo),
        44);

    AssertEqual(
        "2a449ee755e6b892bbedbc8c9523e72065f5d90e12502d5a5f60adfbf885d3b5b956b87f4308a6d8",
        transfer.TransactionHash,
        "transfer hash");
    using var payload = JsonDocument.Parse(transfer.TransactionInfo);
    AssertEqual(12, transfer.TransactionType, "transfer type");
    AssertEqual(32, payload.RootElement.GetProperty("Memo").GetArrayLength(), "transfer memo encoding");
    AssertEqual(17L, payload.RootElement.GetProperty("USDCFee").GetInt64(), "transfer fee");
    AssertEqual(string.Empty, payload.RootElement.GetProperty("L1Sig").GetString()!, "transfer L1 signature");
    return Task.CompletedTask;
}

// The known-answer hashes below were generated with the official Go signer,
// github.com/elliottech/lighter-go v1.0.8-0.20260806100336-17f2d60e4cf5 (commit 17f2d60e4cf5),
// by constructing each txtypes.L2*TxInfo with these exact values and calling Hash(304).
static Task TestDefaultOrderExpiryAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var now = DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_433);
    var clock = new FixedTimeProvider(now);
    var defaulted = new LighterSigner(privateKey, 1, 0, 304, clock).SignCreateOrder(
        new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, LighterSigner.Default28DayOrderExpiry),
        42);
    var expectedExpiry = now.AddDays(28).ToUnixTimeMilliseconds();
    using (var payload = JsonDocument.Parse(defaulted.TransactionInfo))
    {
        AssertEqual(expectedExpiry, payload.RootElement.GetProperty("OrderExpiry").GetInt64(), "defaulted order expiry");
    }

    var explicitOrder = new LighterSigner(privateKey, 1, 0, 304, clock).SignCreateOrder(
        new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, expectedExpiry),
        42);
    AssertEqual(explicitOrder.TransactionHash, defaulted.TransactionHash, "defaulted expiry hash");
    return Task.CompletedTask;
}

static Task TestModifyOrderHashAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_436));
    var signer = new LighterSigner(privateKey, 1, 0, 304, clock);
    var modify = signer.SignModifyOrder(
        new ModifyOrderRequest(7, 281_474_976_710_700, 10, 1_000_000, 0),
        45);
    AssertEqual(
        "eb878794bbe31fd893b06c4054726538b054e62419ba34455f9f1fbaff7205fe537c04d1b0f6376c",
        modify.TransactionHash,
        "modify-order hash");
    AssertEqual(17, modify.TransactionType, "modify-order type");
    using var payload = JsonDocument.Parse(modify.TransactionInfo);
    AssertEqual(281_474_976_710_700L, payload.RootElement.GetProperty("Index").GetInt64(), "modify payload index");
    AssertEqual(0L, payload.RootElement.GetProperty("TriggerPrice").GetInt64(), "modify payload trigger price");
    AssertEqual(JsonValueKind.Null, payload.RootElement.GetProperty("L2TxAttributes").ValueKind, "modify attributes encoding");
    AssertEqual(80, Convert.FromBase64String(payload.RootElement.GetProperty("Sig").GetString()!).Length, "modify signature length");
    return Task.CompletedTask;
}

static Task TestUpdateLeverageHashAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_437));
    var leverage = new LighterSigner(privateKey, 1, 0, 304, clock).SignUpdateLeverage(7, 500, (byte)MarginMode.Isolated, 46);
    AssertEqual(
        "1c41dd2bdb1d2b0fdc22441efeffb78d8370a66c12d7216501a60a31dd26068a648e9ee267363998",
        leverage.TransactionHash,
        "update-leverage hash");
    AssertEqual(20, leverage.TransactionType, "update-leverage type");
    using var payload = JsonDocument.Parse(leverage.TransactionInfo);
    AssertEqual(500L, payload.RootElement.GetProperty("InitialMarginFraction").GetInt64(), "leverage payload margin fraction");
    AssertEqual(1L, payload.RootElement.GetProperty("MarginMode").GetInt64(), "leverage payload margin mode");

    var rawByte = new LighterSigner(privateKey, 1, 0, 304, clock).SignUpdateLeverage(7, 500, 1, 46);
    AssertEqual(leverage.TransactionHash, rawByte.TransactionHash, "margin-mode enum equivalence");
    return Task.CompletedTask;
}

static Task TestApproveIntegratorHashAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_438));
    var approval = new LighterSigner(privateKey, 1, 0, 304, clock).SignApproveIntegrator(
        new ApproveIntegratorRequest(12_345, 100, 50, 100, 50, 1_999_999_999_999),
        47);
    AssertEqual(
        "445d06dce882609734cae5f9b0369e237a72e4d5649befc6773d15a8c6571702f0973ee0bcbdf8e1",
        approval.TransactionHash,
        "approve-integrator hash");
    AssertEqual(45, approval.TransactionType, "approve-integrator type");
    using (var payload = JsonDocument.Parse(approval.TransactionInfo))
    {
        AssertEqual(12_345L, payload.RootElement.GetProperty("IntegratorAccountIndex").GetInt64(), "approval payload integrator");
        AssertEqual(string.Empty, payload.RootElement.GetProperty("L1Sig").GetString()!, "approval payload L1 signature");
        AssertEqual(JsonValueKind.Null, payload.RootElement.GetProperty("L2TxAttributes").ValueKind, "approval attributes encoding");
    }

    var revocation = new LighterSigner(privateKey, 1, 0, 304, clock).SignApproveIntegrator(
        new ApproveIntegratorRequest(12_345, 0, 0, 0, 0, 0),
        48);
    AssertEqual(
        "e92984d27ed4aab23231ebb353776451579cca06b061ad58eb740744c5604c994583c4a2971ac02a",
        revocation.TransactionHash,
        "approve-integrator revocation hash");
    return Task.CompletedTask;
}

static Task TestAttributeAggregationAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var order = new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999);
    var createClock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_433));

    var skipNonce = new LighterSigner(privateKey, 1, 0, 304, createClock).SignCreateOrder(
        order,
        42,
        new L2TxAttributes { SkipNonce = 1 });
    AssertEqual(
        "c30d19e1e9009ffb450bc176a198c4d3b3f7bff6c3c25e0ae60aec912741a13954226166dc9dbde4",
        skipNonce.TransactionHash,
        "skip-nonce aggregated hash");
    using (var payload = JsonDocument.Parse(skipNonce.TransactionInfo))
    {
        AssertEqual(1L, payload.RootElement.GetProperty("L2TxAttributes").GetProperty("4").GetInt64(), "skip-nonce attribute encoding");
    }

    var integrator = new LighterSigner(privateKey, 1, 0, 304, createClock).SignCreateOrder(
        order,
        42,
        new L2TxAttributes { IntegratorAccountIndex = 12_345, IntegratorTakerFee = 400, IntegratorMakerFee = 200 });
    AssertEqual(
        "c3023ce4c0cd19e19c3129358e67b71ef44a89b82c58fb06cb0a166ba2d40928fcbe9cfb6dda515b",
        integrator.TransactionHash,
        "integrator aggregated hash");
    using (var payload = JsonDocument.Parse(integrator.TransactionInfo))
    {
        var attributes = payload.RootElement.GetProperty("L2TxAttributes");
        AssertEqual(12_345L, attributes.GetProperty("1").GetInt64(), "integrator index attribute encoding");
        AssertEqual(400L, attributes.GetProperty("2").GetInt64(), "integrator taker-fee attribute encoding");
        AssertEqual(200L, attributes.GetProperty("3").GetInt64(), "integrator maker-fee attribute encoding");
    }

    var modifyClock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_436));
    var selfTrade = new LighterSigner(privateKey, 1, 0, 304, modifyClock).SignModifyOrder(
        new ModifyOrderRequest(7, 281_474_976_710_700, 10, 1_000_000, 0),
        45,
        new L2TxAttributes
        {
            SelfTradeBehaviorMode = (byte)SelfTradeBehavior.CancelBoth,
            SelfTradeEqualityMode = (byte)SelfTradeEquality.MasterAccountIndex,
        });
    AssertEqual(
        "325deb320a95150adf84a907d1e5a97ca15c7a3ef697741cae84eaede3bcac8fc5e4a28e4130fed5",
        selfTrade.TransactionHash,
        "self-trade aggregated hash");
    using (var payload = JsonDocument.Parse(selfTrade.TransactionInfo))
    {
        var attributes = payload.RootElement.GetProperty("L2TxAttributes");
        AssertEqual(2L, attributes.GetProperty("6").GetInt64(), "self-trade behavior attribute encoding");
        AssertEqual(1L, attributes.GetProperty("7").GetInt64(), "self-trade equality attribute encoding");
    }

    return Task.CompletedTask;
}

static Task TestMarketOrderHashAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_439));
    var market = new LighterSigner(privateKey, 1, 0, 304, clock).SignCreateOrder(
        OrderRequest.Create(7, 124, 10, 1_000_000, false, OrderType.Market, OrderTimeInForce.ImmediateOrCancel, false, 0, 0),
        49);
    AssertEqual(
        "4448881705390f3aae29a05cc9520738cb5467b3ccd165ba73786927d9b973e8cd1125189c7895f7",
        market.TransactionHash,
        "market-order hash");
    return Task.CompletedTask;
}

static Task TestNilAttributesPreserveHashAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_433));
    var nilValued = new LighterSigner(privateKey, 1, 0, 304, clock).SignCreateOrder(
        new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999),
        42,
        new L2TxAttributes { IntegratorAccountIndex = 0, SelfTradeBehaviorMode = 0 });
    AssertEqual(
        "aa8f0203aa47fd2f9c82b85d96a3228b40884ebf2bd7cc6e21668f0a7e5ba16e2b6f3214af822fa6",
        nilValued.TransactionHash,
        "nil-valued attributes hash");
    using var payload = JsonDocument.Parse(nilValued.TransactionInfo);
    var attributes = payload.RootElement.GetProperty("L2TxAttributes");
    AssertEqual(0L, attributes.GetProperty("1").GetInt64(), "nil integrator attribute encoding");
    AssertEqual(0L, attributes.GetProperty("6").GetInt64(), "nil self-trade attribute encoding");
    return Task.CompletedTask;
}

static Task TestAttributeValidationAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_433));
    var signer = new LighterSigner(privateKey, 1, 0, 304, clock);
    var order = new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999);
    SignedTransaction Sign(L2TxAttributes attributes) => signer.SignCreateOrder(order, 42, attributes);

    AssertThrows<ArgumentException>(
        () => Sign(new L2TxAttributes
        {
            IntegratorAccountIndex = 1_000,
            IntegratorTakerFee = 400,
            IntegratorMakerFee = 0,
            SkipNonce = 1,
            SelfTradeBehaviorMode = 0,
        }),
        "more than four attributes (nil-valued entries count)");
    AssertThrows<ArgumentException>(
        () => Sign(new L2TxAttributes { IntegratorTakerFee = 400 }),
        "fees without an integrator account index");
    AssertThrows<ArgumentException>(
        () => Sign(new L2TxAttributes { IntegratorAccountIndex = 1_000, IntegratorTakerFee = 400, SelfTradeBehaviorMode = 1 }),
        "fees combined with self-trade attributes");
    AssertThrows<ArgumentException>(
        () => Sign(new L2TxAttributes
        {
            SelfTradeBehaviorMode = (byte)SelfTradeBehavior.Reduce,
            SelfTradeEqualityMode = (byte)SelfTradeEquality.MasterAccountIndex,
        }),
        "reduce behavior with master-account equality");
    AssertThrows<ArgumentException>(
        () => Sign(new L2TxAttributes { SkipNonce = 0 }),
        "skip nonce zero");
    AssertThrows<ArgumentException>(
        () => Sign(new L2TxAttributes { SkipNonce = 2 }),
        "skip nonce above one");
    AssertThrows<ArgumentException>(
        () => Sign(new L2TxAttributes { IntegratorAccountIndex = 1_000, IntegratorTakerFee = 1_000_001 }),
        "fee above the fee tick");
    AssertThrows<ArgumentException>(
        () => Sign(new L2TxAttributes { IntegratorAccountIndex = 281_474_976_710_655 }),
        "integrator account index above the maximum");
    return Task.CompletedTask;
}

static Task TestOrderValidationAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_433));
    var signer = new LighterSigner(privateKey, 1, 0, 304, clock);
    const long expiry = 1_999_999_999_999;

    AssertThrows<ArgumentException>(
        () => signer.SignCreateOrder(new OrderRequest(7, 125, 10, 100, false, 1, 1, false, 0, 0), 50),
        "market order with good-till-time");
    AssertThrows<ArgumentException>(
        () => signer.SignCreateOrder(new OrderRequest(7, 125, 10, 100, false, 0, 0, false, 0, expiry), 50),
        "immediate-or-cancel limit order with an expiry");
    AssertThrows<ArgumentException>(
        () => signer.SignCreateOrder(new OrderRequest(7, 125, 10, 100, false, 0, 1, false, 0, 0), 50),
        "good-till-time limit order without an expiry");
    AssertThrows<ArgumentException>(
        () => signer.SignCreateOrder(new OrderRequest(2048, 125, 10, 100, false, 2, 0, false, 90, expiry), 50),
        "stop-loss order on a spot market");
    AssertThrows<ArgumentException>(
        () => signer.SignCreateOrder(new OrderRequest(7, 125, 10, 100, false, 6, 0, false, 0, expiry), 50),
        "TWAP order with immediate-or-cancel");
    AssertThrows<ArgumentException>(
        () => signer.SignCreateOrder(new OrderRequest(2048, 125, 10, 100, false, 0, 1, true, 0, expiry), 50),
        "reduce-only order on a spot market");
    AssertThrows<ArgumentException>(
        () => signer.SignCreateOrder(new OrderRequest(7, 125, 10, 100, false, 7, 1, false, 0, expiry), 50),
        "unknown order type");

    AssertEqual(
        14,
        signer.SignCreateOrder(new OrderRequest(7, 0, 10, 100, false, 0, 1, false, 0, expiry), 50).TransactionType,
        "nil client order index signs");
    AssertEqual(
        14,
        signer.SignCreateOrder(new OrderRequest(2048, 126, 10, 100, false, 0, 1, false, 0, expiry), 50).TransactionType,
        "spot-market limit order signs");
    AssertEqual(
        14,
        signer.SignCreateOrder(new OrderRequest(7, 127, 10, 100, false, 2, 0, false, 95, expiry), 50).TransactionType,
        "perpetual stop-loss order signs");
    return Task.CompletedTask;
}

static Task TestEnumFactoryAsync()
{
    var byteOrder = new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999);
    var enumOrder = OrderRequest.Create(
        7, 123, 10, 1_000_000, false, OrderType.Limit, OrderTimeInForce.GoodTillTime, false, 0, 1_999_999_999_999);
    AssertEqual(byteOrder, enumOrder, "enum factory equality");
    return Task.CompletedTask;
}

static Task TestTransactionExpiryAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var now = DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_433);
    var signer = new LighterSigner(privateKey, 1, 0, 304, new FixedTimeProvider(now))
    {
        TransactionExpiry = TimeSpan.FromMinutes(5),
    };
    var cancel = signer.SignCancelOrder(7, 281_474_976_710_700, 43);
    using (var payload = JsonDocument.Parse(cancel.TransactionInfo))
    {
        AssertEqual(
            now.AddMinutes(5).ToUnixTimeMilliseconds(),
            payload.RootElement.GetProperty("ExpiredAt").GetInt64(),
            "custom transaction expiry");
    }

    AssertEqual(
        LighterSigner.DefaultTransactionExpiry,
        new LighterSigner(privateKey, 1, 0, 304).TransactionExpiry,
        "default transaction expiry");
    AssertThrows<ArgumentOutOfRangeException>(() => signer.TransactionExpiry = TimeSpan.Zero, "zero transaction expiry");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.TransactionExpiry = TimeSpan.FromSeconds(-1),
        "negative transaction expiry");
    return Task.CompletedTask;
}

static Task TestNegativeAndSpotInputHashesAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";

    // Go hashes signed values via a two's-complement cast, so -1 becomes 2^32 - 2 mod p.
    var approvalClock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_440));
    var negativeIntegrator = new LighterSigner(privateKey, 1, 0, 304, approvalClock).SignApproveIntegrator(
        new ApproveIntegratorRequest(-1, 100, 50, 100, 50, 1_999_999_999_999),
        50);
    AssertEqual(
        "f6988783cbb5c36b1c907d05eba46cf362b3bf84e2b2a5afc3b0c76a111cddc33f64fb18a7193ff0",
        negativeIntegrator.TransactionHash,
        "negative integrator index hash");

    var leverageClock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_441));
    var negativeMarket = new LighterSigner(privateKey, 1, 0, 304, leverageClock).SignUpdateLeverage(-1, 500, 0, 51);
    AssertEqual(
        "99423782871fb3b06e0655cb4f49a3e689daa608ab4091dbf6bbfc35c073489b0f506cb7e05e2f50",
        negativeMarket.TransactionHash,
        "negative leverage market hash");

    var cancelClock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_548_442));
    var spotCancel = new LighterSigner(privateKey, 1, 0, 304, cancelClock).SignCancelOrder(2048, 281_474_976_710_700, 52);
    AssertEqual(
        "8c9def27ab316cf32a8478353460f5174d67adada531648efff455989ea278e7a7646a7f2c5e85b7",
        spotCancel.TransactionHash,
        "spot-market cancel hash");

    var strictSigner = new LighterSigner(privateKey, 1, 0, 304, cancelClock);
    AssertThrows<ArgumentOutOfRangeException>(
        () => strictSigner.SignCancelOrder(7, 1L << 60, 52),
        "cancel index above the maximum");
    AssertThrows<ArgumentOutOfRangeException>(
        () => new LighterSigner(privateKey, 1, 255, 304, cancelClock),
        "nil api key index");
    return Task.CompletedTask;
}

static Task TestPublicSurfaceAsync()
{
    var expected = new[]
    {
        "Lighter.Signer.LighterSigner",
        "Lighter.Signer.Transactions.ApproveIntegratorRequest",
        "Lighter.Signer.Transactions.L2TxAttributes",
        "Lighter.Signer.Transactions.MarginMode",
        "Lighter.Signer.Transactions.ModifyOrderRequest",
        "Lighter.Signer.Transactions.OrderRequest",
        "Lighter.Signer.Transactions.OrderTimeInForce",
        "Lighter.Signer.Transactions.OrderType",
        "Lighter.Signer.Transactions.SelfTradeBehavior",
        "Lighter.Signer.Transactions.SelfTradeEquality",
        "Lighter.Signer.Transactions.SignedTransaction",
        "Lighter.Signer.Transactions.TransferRequest",
    };
    var actual = typeof(LighterSigner).Assembly
        .GetExportedTypes()
        .Select(type => type.FullName!)
        .Order(StringComparer.Ordinal)
        .ToArray();

    AssertSequenceEqual(expected, actual, "public signer API surface");
    return Task.CompletedTask;
}

static async Task TestRestWireContractAsync()
{
    var handler = new ContractHandler();
    using var httpClient = new HttpClient(handler);
    var profile = new EndpointProfile("test", new Uri("https://lighter.invalid/"), 304);
    await using var api = new LighterApiClient(profile, httpClient);
    var transaction = new SignedTransaction(14, "{\"AccountIndex\":1}", "hash");
    var response = await api.SendTransactionAsync(transaction, CancellationToken.None);
    AssertEqual(200, response.Code, "sendTx response");
    var orders = await api.GetOpenOrdersAsync(1, "auth-token", CancellationToken.None);
    AssertEqual(0, orders.Orders.Count, "open-order response");
    AssertEqual(true, handler.SawFormContract, "sendTx form contract");
    AssertEqual(true, handler.SawAuthorizationHeader, "active-order auth contract");
}

static async Task TestRestFailureAsync()
{
    using var httpClient = new HttpClient(new RejectionHandler());
    var profile = new EndpointProfile("test", new Uri("https://lighter.invalid/"), 304);
    await using var api = new LighterApiClient(profile, httpClient);
    var transaction = new SignedTransaction(14, "{\"AccountIndex\":1}", "hash");

    try
    {
        await api.SendTransactionAsync(transaction, CancellationToken.None);
        throw new InvalidOperationException("REST client accepted a rejected transaction.");
    }
    catch (LighterApiException exception)
    {
        AssertContains("minimum base amount", exception.Message);
    }
}

static async Task TestSevenGoalStepsAsync()
{
    const string privateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";
    var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_557_433));
    var credentials = new ApiCredentials("unused", privateKey, 987_654, "unused", 13);
    var signer = new LighterSigner(privateKey, 987_654, 13, 304, clock);
    var fakeExchange = new StatefulFakeExchange();
    using var output = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
    var workflow = new TradingWorkflow(
        fakeExchange,
        credentials,
        signer,
        output,
        clock,
        (_, _) => Task.CompletedTask);

    await workflow.RunAsync(CancellationToken.None);
    var text = output.ToString();
    AssertContains("1. Balances count: 2", text);
    AssertContains("2. Placed order ID: exchange-order-123", text);
    AssertContains("3. Open orders count: 1", text);
    AssertContains("4. Placed order ID is present in open orders: yes", text);
    AssertContains("5. Cancel submitted for exchange order ID: exchange-order-123", text);
    AssertContains("6. Open orders count: 0", text);
    AssertContains("7. Placed order ID is absent from open orders: yes", text);
    AssertEqual(20L, fakeExchange.CreatedBaseAmount, "authorized XRP order amount");
    AssertContains("\"AccountIndex\":\"[REDACTED]\"", text);
    AssertContains("\"ApiKeyIndex\":\"[REDACTED]\"", text);
    AssertContains("\"Sig\":\"[REDACTED]\"", text);
    AssertDoesNotContain("\"AccountIndex\":987654", text);
    AssertDoesNotContain("\"ApiKeyIndex\":13", text);
    AssertEqual(true, fakeExchange.CancelUsedExchangeOrderIndex, "cancel exchange order index");
}

static Scalar ScalarFromLimbs(params ulong[] limbs)
{
    if (limbs.Length != 5)
    {
        throw new ArgumentException("Exactly five limbs are required.", nameof(limbs));
    }

    var bytes = new byte[40];
    for (var index = 0; index < limbs.Length; index++)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(index * 8, 8), limbs[index]);
    }

    return new Scalar(new BigInteger(bytes, isUnsigned: true, isBigEndian: false));
}

static void AssertEqual<T>(T expected, T actual, string description)
    where T : notnull
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"{description}: expected {expected}, received {actual}");
    }
}

static void AssertSequenceEqual<T>(IEnumerable<T> expected, IEnumerable<T> actual, string description)
    where T : notnull
{
    var expectedArray = expected.ToArray();
    var actualArray = actual.ToArray();
    if (!expectedArray.SequenceEqual(actualArray))
    {
        throw new InvalidOperationException(
            $"{description} did not match. Expected [{string.Join(',', expectedArray)}], actual [{string.Join(',', actualArray)}].");
    }
}

static void AssertThrows<TException>(Action action, string description)
    where TException : Exception
{
    try
    {
        action();
    }
    catch (TException)
    {
        return;
    }
    catch (Exception exception)
    {
        throw new InvalidOperationException(
            $"{description}: threw {exception.GetType().Name} instead of {typeof(TException).Name}");
    }

    throw new InvalidOperationException($"{description}: no exception was thrown");
}

static void AssertContains(string expected, string actual)
{
    if (!actual.Contains(expected, StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"Output did not contain: {expected}");
    }
}

static void AssertDoesNotContain(string unexpected, string actual)
{
    if (actual.Contains(unexpected, StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"Output contained sensitive value marker: {unexpected}");
    }
}

sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => value;
}

sealed class ContractHandler : HttpMessageHandler
{
    public bool SawFormContract { get; private set; }

    public bool SawAuthorizationHeader { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        if (request.RequestUri!.AbsolutePath.EndsWith("/sendTx", StringComparison.Ordinal))
        {
            var body = await request.Content!.ReadAsStringAsync(cancellationToken);
            SawFormContract = request.Content.Headers.ContentType?.MediaType == "application/x-www-form-urlencoded" &&
                              body.Contains("tx_type=14", StringComparison.Ordinal) &&
                              body.Contains("tx_info=", StringComparison.Ordinal);
            return Json("{\"code\":200,\"tx_hash\":\"hash\",\"predicted_execution_time_ms\":1}");
        }

        if (request.RequestUri.AbsolutePath.EndsWith("/accountActiveOrders", StringComparison.Ordinal))
        {
            SawAuthorizationHeader = request.Headers.TryGetValues("authorization", out var values) &&
                                     values.Single() == "auth-token";
            return Json("{\"code\":200,\"orders\":[]}");
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json(string content) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(content, Encoding.UTF8, "application/json"),
    };
}

sealed class RejectionHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken) =>
        Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(
                "{\"code\":21105,\"message\":\"minimum base amount is 20\"}",
                Encoding.UTF8,
                "application/json"),
        });
}

sealed class StatefulFakeExchange : ILighterApiClient
{
    private OpenOrder? _openOrder;

    public bool CancelUsedExchangeOrderIndex { get; private set; }

    public long CreatedBaseAmount { get; private set; }

    public Task<Account> GetAccountAsync(long accountIndex, CancellationToken cancellationToken) =>
        Task.FromResult(new Account
        {
            Assets = [new AccountAsset(), new AccountAsset()],
            Positions = [new AccountPosition()],
        });

    public Task<string?> GetApiPublicKeyAsync(long accountIndex, byte apiKeyIndex, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(null);

    public Task<long> GetNextNonceAsync(long accountIndex, byte apiKeyIndex, CancellationToken cancellationToken) =>
        Task.FromResult(42L);

    public Task<MarketDetails> GetMarketAsync(string symbol, CancellationToken cancellationToken) =>
        Task.FromResult(new MarketDetails
        {
            Symbol = "XRP",
            MarketId = 7,
            Status = "active",
            MinimumBaseAmount = "1",
            SupportedSizeDecimals = 0,
            SupportedPriceDecimals = 6,
        });

    public Task<OrdersResponse> GetOpenOrdersAsync(
        long accountIndex,
        string authToken,
        CancellationToken cancellationToken) =>
        Task.FromResult(new OrdersResponse
        {
            Code = 200,
            Orders = _openOrder is null ? [] : [_openOrder],
        });

    public Task<SendTransactionResponse> SendTransactionAsync(
        SignedTransaction transaction,
        CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(transaction.TransactionInfo);
        if (transaction.TransactionType == LighterSigner.CreateOrderTransactionType)
        {
            CreatedBaseAmount = document.RootElement.GetProperty("BaseAmount").GetInt64();
            _openOrder = new OpenOrder
            {
                ClientOrderIndex = document.RootElement.GetProperty("ClientOrderIndex").GetInt64(),
                MarketIndex = document.RootElement.GetProperty("MarketIndex").GetInt16(),
                OrderIndex = 281_474_976_710_700,
                OrderId = "exchange-order-123",
            };
        }
        else if (transaction.TransactionType == LighterSigner.CancelOrderTransactionType)
        {
            CancelUsedExchangeOrderIndex = document.RootElement.GetProperty("Index").GetInt64() == _openOrder?.OrderIndex;
            _openOrder = null;
        }

        return Task.FromResult(new SendTransactionResponse
        {
            Code = 200,
            Message = "success",
            TransactionHash = transaction.TransactionHash,
            PredictedExecutionTimeMilliseconds = 1,
        });
    }
}
