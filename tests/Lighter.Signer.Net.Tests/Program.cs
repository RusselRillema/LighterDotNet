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

const string TestPrivateKey = "01010101010101010101010101010101010101010101010101010101010101010101010101010101";

// hex("official-transfer-vector") zero-padded to 32 bytes — same bytes as the original vector.
const string VectorMemoHex = "6f6666696369616c2d7472616e736665722d766563746f720000000000000000";

(string Name, Func<Task> Run)[] tests =
[
    ("Poseidon2 matches official vector", TestPoseidon2Async),
    ("Schnorr matches official deterministic vector", TestSchnorrAsync),
    ("Transaction hashes match official Go signer", TestTransactionHashesAsync),
    ("Sub-account transfer matches official Go signer", TestTransferHashAsync),
    ("Transfer memo decoding matches Go signer rules", TestTransferMemoDecodingAsync),
    ("Transfer bounds match official Go signer", TestTransferBoundsAsync),
    ("Modify, leverage, and approval validation reject invalid inputs", TestNewValidatorRejectionsAsync),
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
    ("L1 signature attaches to approve-integrator payload", TestL1SignatureAttachmentAsync),
    ("Package exposes only signer API types", TestPublicSurfaceAsync),
    ("REST client uses official wire contract", TestRestWireContractAsync),
    ("REST client surfaces exchange rejection", TestRestFailureAsync),
    ("Seven-step workflow state machine passes", TestSevenGoalStepsAsync),
];

foreach ((string Name, Func<Task> Run) test in tests)
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
    ulong[] fieldInputs = [0, 1, 2, Goldilocks.Modulus - 1, ulong.MaxValue, 15_492_826_721_047_263_190];
    foreach (ulong left in fieldInputs)
    {
        foreach (ulong right in fieldInputs)
        {
            ulong expectedProduct = (ulong)((new BigInteger(left) * right) % Goldilocks.Modulus);
            ulong actualProduct = (new Goldilocks(left) * new Goldilocks(right)).Value;
            AssertEqual(expectedProduct, actualProduct, "Goldilocks multiplication");
            ulong expectedSum = (ulong)((new BigInteger(left) + right) % Goldilocks.Modulus);
            ulong actualSum = (new Goldilocks(left) + new Goldilocks(right)).Value;
            AssertEqual(expectedSum, actualSum, "Goldilocks addition");
        }
    }

    Goldilocks[] state =
    [
        5_417_613_058_500_526_590, 2_481_548_824_842_427_254, 6_473_243_198_879_784_792,
        1_720_313_757_066_167_274, 2_806_320_291_675_974_571, 7_407_976_414_706_455_446,
        1_105_257_841_424_046_885, 7_613_435_757_403_328_049, 3_376_066_686_066_811_538,
        5_888_575_799_323_675_710, 6_689_309_723_188_675_948, 2_468_250_420_241_012_720,
    ];
    ulong[] expected =
    [
        5_364_184_781_011_389_007, 15_309_475_861_242_939_136, 5_983_386_513_087_443_499,
        886_942_118_604_446_276, 14_903_657_885_227_062_600, 7_742_650_891_575_941_298,
        1_962_182_278_500_985_790, 10_213_480_816_595_178_755, 3_510_799_061_817_443_836,
        4_610_029_967_627_506_430, 7_566_382_334_276_534_836, 2_288_460_879_362_380_348,
    ];

    Poseidon2.Permute(state);
    AssertSequenceEqual(expected, state.Select(item => item.Value), "Poseidon2 permutation");
    return Task.CompletedTask;
}

static Task TestSchnorrAsync()
{
    Scalar privateKey = ScalarFromLimbs(
        12_235_002_942_052_073_545, 1_175_977_464_658_719_998, 8_536_934_969_147_463_310,
        6_524_687_619_313_720_391, 2_922_072_024_880_609_112);
    Scalar nonce = ScalarFromLimbs(
        5_245_666_847_777_449_560, 15_178_169_970_799_106_939, 4_403_065_012_435_293_749,
        15_306_540_389_399_388_999, 8_935_555_081_913_173_844);
    Fp5 hashedMessage = new(
        8_398_652_514_106_806_347, 11_069_112_711_939_986_896, 9_732_488_227_085_561_369,
        18_076_754_337_204_438_535, 17_155_407_358_725_346_236);
    Scalar expectedS = ScalarFromLimbs(
        6_950_590_877_883_398_434, 17_178_336_263_794_770_543, 11_012_823_478_139_181_320,
        16_445_091_359_523_510_936, 5_882_925_226_143_600_273);
    Scalar expectedE = ScalarFromLimbs(
        4_544_744_459_434_870_309, 4_180_764_085_957_612_004, 3_024_669_018_778_978_615,
        15_433_417_688_859_446_606, 6_775_027_260_348_937_828);

    SchnorrSigner signer = new(Convert.ToHexString(privateKey.ToLittleEndianBytes()));
    SchnorrSignature signature = signer.Sign(hashedMessage, nonce);
    AssertEqual(expectedS, signature.S, "Schnorr S");
    AssertEqual(expectedE, signature.E, "Schnorr E");
    return Task.CompletedTask;
}

// The known-answer transaction hashes in the tests below were generated with the official Go
// signer, github.com/elliottech/lighter-go, by constructing each txtypes.L2*TxInfo with these exact
// values and calling Hash(304). The order-version vectors need a lighter-go that supports attribute 8.
static Task TestTransactionHashesAsync()
{
    SignedTransaction create = CreateTestSigner(1_784_267_548_433).SignCreateOrder(new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999), 42);
    AssertEqual(
        "aa8f0203aa47fd2f9c82b85d96a3228b40884ebf2bd7cc6e21668f0a7e5ba16e2b6f3214af822fa6",
        create.TransactionHash,
        "create-order hash");
    using (JsonDocument payload = JsonDocument.Parse(create.TransactionInfo))
    {
        AssertEqual(10L, payload.RootElement.GetProperty("BaseAmount").GetInt64(), "create payload amount");
        AssertEqual(JsonValueKind.Null, payload.RootElement.GetProperty("L2TxAttributes").ValueKind, "attributes encoding");
        AssertEqual(80, Convert.FromBase64String(payload.RootElement.GetProperty("Sig").GetString()!).Length, "signature length");
    }

    SignedTransaction cancel = CreateTestSigner(1_784_267_548_434).SignCancelOrder(7, 281_474_976_710_700, 43);
    AssertEqual(
        "8a64d7b716470b2b9cc4e754d77a672d0b6e8ec88b8680c16843a166593a737a4b72ca78387f0ff6",
        cancel.TransactionHash,
        "cancel-order hash");
    return Task.CompletedTask;
}

static Task TestTransferHashAsync()
{
    SignedTransaction transfer = CreateTestSigner(1_784_267_548_435).SignTransfer(new TransferRequest(2, 1, 0, 1, 4_294_967_299, 17, VectorMemoHex), 44);

    AssertEqual(
        "2a449ee755e6b892bbedbc8c9523e72065f5d90e12502d5a5f60adfbf885d3b5b956b87f4308a6d8",
        transfer.TransactionHash,
        "transfer hash");
    using JsonDocument payload = JsonDocument.Parse(transfer.TransactionInfo);
    AssertEqual(12, transfer.TransactionType, "transfer type");
    AssertEqual(32, payload.RootElement.GetProperty("Memo").GetArrayLength(), "transfer memo encoding");
    AssertEqual(111L, payload.RootElement.GetProperty("Memo")[0].GetInt64(), "transfer memo first byte");
    AssertEqual(17L, payload.RootElement.GetProperty("USDCFee").GetInt64(), "transfer fee");
    AssertEqual(string.Empty, payload.RootElement.GetProperty("L1Sig").GetString()!, "transfer L1 signature");
    AssertEqual(true, transfer.L1SignatureBody is null, "transfer L1 signature body absent");
    return Task.CompletedTask;
}

static Task TestTransferMemoDecodingAsync()
{
    SignedTransaction Sign(string memo) => CreateTestSigner(1_784_267_548_435).SignTransfer(new TransferRequest(2, 1, 0, 1, 4_294_967_299, 17, memo), 44);

    // The three accepted forms of the same 32 bytes produce identical hashes.
    string rawMemo = new('a', 32);
    string rawMemoHex = string.Concat(Enumerable.Repeat("61", 32));
    SignedTransaction raw = Sign(rawMemo);
    AssertEqual(raw.TransactionHash, Sign(rawMemoHex).TransactionHash, "raw memo equals hex memo");
    AssertEqual(raw.TransactionHash, Sign("0x" + rawMemoHex).TransactionHash, "raw memo equals 0x-prefixed memo");

    // Matching Go, anything that is not exactly 32 bytes / 64 hex / 0x + 64 hex is rejected.
    AssertThrows<ArgumentException>(() => Sign(new string('a', 31)), "31-character memo");
    AssertThrows<ArgumentException>(() => Sign(new string('a', 33)), "33-character memo");
    AssertThrows<ArgumentException>(() => Sign(new string('z', 64)), "64 non-hex characters");
    AssertThrows<ArgumentException>(() => Sign(new string('a', 66)), "66 characters without 0x prefix");
    return Task.CompletedTask;
}

static Task TestTransferBoundsAsync()
{
    // Matching Go, the treasury account (0) and -1 pass destination validation.
    AssertEqual(
        "4cfca04c7a41decfdb7c1c1269776ba79130688809c02a9dc7f4f7275c24d7579ebfbfd2acefa5f7",
        CreateTestSigner(1_784_267_548_443)
            .SignTransfer(new TransferRequest(0, 1, 0, 1, 4_294_967_299, 17, VectorMemoHex), 53)
            .TransactionHash,
        "treasury transfer hash");
    AssertEqual(
        "ed1c4afbcff920ddf8557f9d2a7efe7038b5b03234639879f145eb00073ad0d1d4c3e1de8d09cc3c",
        CreateTestSigner(1_784_267_548_444)
            .SignTransfer(new TransferRequest(-1, 1, 0, 1, 4_294_967_299, 17, VectorMemoHex), 54)
            .TransactionHash,
        "negative-one transfer hash");

    LighterSigner signer = CreateTestSigner(1_784_267_548_443);
    SignedTransaction Sign(TransferRequest transfer) => signer.SignTransfer(transfer, 53);
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new TransferRequest(2, 0, 0, 1, 100, 0, VectorMemoHex)),
        "nil asset index");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new TransferRequest(2, 63, 0, 1, 100, 0, VectorMemoHex)),
        "asset index above the maximum");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new TransferRequest(2, 1, 0, 1, 1L << 60, 0, VectorMemoHex)),
        "amount above the maximum");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new TransferRequest(2, 1, 0, 1, 100, 1L << 60, VectorMemoHex)),
        "fee above the maximum");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new TransferRequest(281_474_976_710_655, 1, 0, 1, 100, 0, VectorMemoHex)),
        "destination above the maximum");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new TransferRequest(-2, 1, 0, 1, 100, 0, VectorMemoHex)),
        "destination below the minimum");
    return Task.CompletedTask;
}

static Task TestNewValidatorRejectionsAsync()
{
    LighterSigner signer = CreateTestSigner(1_784_267_548_433);

    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignModifyOrder(new ModifyOrderRequest(300, 10, 10, 100, 0), 60),
        "modify market between perps and spot");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignModifyOrder(new ModifyOrderRequest(7, 0, 10, 100, 0), 60),
        "modify order index zero");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignModifyOrder(new ModifyOrderRequest(7, 1L << 60, 10, 100, 0), 60),
        "modify order index above the maximum");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignModifyOrder(new ModifyOrderRequest(7, 10, -1, 100, 0), 60),
        "modify negative base amount");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignModifyOrder(new ModifyOrderRequest(7, 10, 10, 0, 0), 60),
        "modify price zero");

    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignUpdateLeverage(255, 500, 0, 60),
        "leverage nil market sentinel");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignUpdateLeverage(7, 500, 2, 60),
        "leverage margin mode above isolated");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignUpdateLeverage(7, 0, 0, 60),
        "leverage zero margin fraction");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignUpdateLeverage(7, 10_001, 0, 60),
        "leverage margin fraction above the tick");

    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignApproveIntegrator(new ApproveIntegratorRequest(-2, 0, 0, 0, 0, 1), 60),
        "integrator index below the minimum");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignApproveIntegrator(new ApproveIntegratorRequest(281_474_976_710_655, 0, 0, 0, 0, 1), 60),
        "integrator index above the maximum");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignApproveIntegrator(new ApproveIntegratorRequest(12_345, 1_000_001, 0, 0, 0, 1), 60),
        "integrator fee above the tick");
    AssertThrows<ArgumentException>(
        () => signer.SignApproveIntegrator(new ApproveIntegratorRequest(12_345, 1, 0, 0, 0, 0), 60),
        "revocation with a non-zero fee");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignApproveIntegrator(new ApproveIntegratorRequest(12_345, 0, 0, 0, 0, -1), 60),
        "negative approval expiry");

    AssertThrows<ArgumentOutOfRangeException>(
        () => new LighterSigner(TestPrivateKey, 281_474_976_710_655, 0, 304),
        "account index above the maximum");
    return Task.CompletedTask;
}

static Task TestDefaultOrderExpiryAsync()
{
    const long nowMilliseconds = 1_784_267_548_433;
    SignedTransaction defaulted = CreateTestSigner(nowMilliseconds).SignCreateOrder(new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, LighterSigner.Default28DayOrderExpiry), 42);
    long expectedExpiry = DateTimeOffset.FromUnixTimeMilliseconds(nowMilliseconds).AddDays(28).ToUnixTimeMilliseconds();
    using (JsonDocument payload = JsonDocument.Parse(defaulted.TransactionInfo))
    {
        AssertEqual(expectedExpiry, payload.RootElement.GetProperty("OrderExpiry").GetInt64(), "defaulted order expiry");
    }

    SignedTransaction explicitOrder = CreateTestSigner(nowMilliseconds).SignCreateOrder(new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, expectedExpiry), 42);
    AssertEqual(explicitOrder.TransactionHash, defaulted.TransactionHash, "defaulted expiry hash");
    return Task.CompletedTask;
}

static Task TestModifyOrderHashAsync()
{
    SignedTransaction modify = CreateTestSigner(1_784_267_548_436).SignModifyOrder(new ModifyOrderRequest(7, 281_474_976_710_700, 10, 1_000_000, 0), 45);
    AssertEqual(
        "eb878794bbe31fd893b06c4054726538b054e62419ba34455f9f1fbaff7205fe537c04d1b0f6376c",
        modify.TransactionHash,
        "modify-order hash");
    AssertEqual(17, modify.TransactionType, "modify-order type");
    using JsonDocument payload = JsonDocument.Parse(modify.TransactionInfo);
    AssertEqual(281_474_976_710_700L, payload.RootElement.GetProperty("Index").GetInt64(), "modify payload index");
    AssertEqual(0L, payload.RootElement.GetProperty("TriggerPrice").GetInt64(), "modify payload trigger price");
    AssertEqual(JsonValueKind.Null, payload.RootElement.GetProperty("L2TxAttributes").ValueKind, "modify attributes encoding");
    AssertEqual(80, Convert.FromBase64String(payload.RootElement.GetProperty("Sig").GetString()!).Length, "modify signature length");
    return Task.CompletedTask;
}

static Task TestUpdateLeverageHashAsync()
{
    SignedTransaction leverage = CreateTestSigner(1_784_267_548_437).SignUpdateLeverage(7, 500, (byte)MarginMode.Isolated, 46);
    AssertEqual(
        "1c41dd2bdb1d2b0fdc22441efeffb78d8370a66c12d7216501a60a31dd26068a648e9ee267363998",
        leverage.TransactionHash,
        "update-leverage hash");
    AssertEqual(20, leverage.TransactionType, "update-leverage type");
    using JsonDocument payload = JsonDocument.Parse(leverage.TransactionInfo);
    AssertEqual(500L, payload.RootElement.GetProperty("InitialMarginFraction").GetInt64(), "leverage payload margin fraction");
    AssertEqual(1L, payload.RootElement.GetProperty("MarginMode").GetInt64(), "leverage payload margin mode");
    return Task.CompletedTask;
}

static Task TestApproveIntegratorHashAsync()
{
    SignedTransaction approval = CreateTestSigner(1_784_267_548_438).SignApproveIntegrator(new ApproveIntegratorRequest(12_345, 100, 50, 100, 50, 1_999_999_999_999), 47);
    AssertEqual(
        "445d06dce882609734cae5f9b0369e237a72e4d5649befc6773d15a8c6571702f0973ee0bcbdf8e1",
        approval.TransactionHash,
        "approve-integrator hash");
    AssertEqual(45, approval.TransactionType, "approve-integrator type");
    using (JsonDocument payload = JsonDocument.Parse(approval.TransactionInfo))
    {
        AssertEqual(12_345L, payload.RootElement.GetProperty("IntegratorAccountIndex").GetInt64(), "approval payload integrator");
        AssertEqual(string.Empty, payload.RootElement.GetProperty("L1Sig").GetString()!, "approval payload L1 signature");
        AssertEqual(JsonValueKind.Null, payload.RootElement.GetProperty("L2TxAttributes").ValueKind, "approval attributes encoding");
    }

    // The L1 signature bodies below were generated by the Go signer's GetL1SignatureBody(304).
    AssertEqual(
        "Approve Integrator\n\nnonce: 0x000000000000002f\naccount index: 0x0000000000000001\napi key index: 0x0000000000000000\n" +
        "integrator account index: 0x0000000000003039\nmax perps taker fee: 0x0000000000000064\nmax perps maker fee: 0x0000000000000032\n" +
        "max spot taker fee: 0x0000000000000064\nmax spot maker fee: 0x0000000000000032\napproval expiry: 0x000001d1a94a1fff\n" +
        "chainId: 0x0000000000000130\nOnly sign this message for a trusted client!",
        approval.L1SignatureBody!,
        "approval L1 signature body");

    SignedTransaction revocation = CreateTestSigner(1_784_267_548_438).SignApproveIntegrator(new ApproveIntegratorRequest(12_345, 0, 0, 0, 0, 0), 48);
    AssertEqual(
        "e92984d27ed4aab23231ebb353776451579cca06b061ad58eb740744c5604c994583c4a2971ac02a",
        revocation.TransactionHash,
        "approve-integrator revocation hash");
    AssertEqual(
        "Approve Integrator\n\nnonce: 0x0000000000000030\naccount index: 0x0000000000000001\napi key index: 0x0000000000000000\n" +
        "integrator account index: 0x0000000000003039\nmax perps taker fee: 0x0000000000000000\nmax perps maker fee: 0x0000000000000000\n" +
        "max spot taker fee: 0x0000000000000000\nmax spot maker fee: 0x0000000000000000\napproval expiry: 0x0000000000000000\n" +
        "chainId: 0x0000000000000130\nOnly sign this message for a trusted client!",
        revocation.L1SignatureBody!,
        "revocation L1 signature body");
    return Task.CompletedTask;
}

static Task TestAttributeAggregationAsync()
{
    OrderRequest order = new(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999);
    L2TxAttributes skipNonceAttributes = new L2TxAttributes { SkipNonce = 1 };

    SignedTransaction skipNonce = CreateTestSigner(1_784_267_548_433).SignCreateOrder(order, 42, skipNonceAttributes);
    AssertEqual(
        "c30d19e1e9009ffb450bc176a198c4d3b3f7bff6c3c25e0ae60aec912741a13954226166dc9dbde4",
        skipNonce.TransactionHash,
        "skip-nonce aggregated hash");
    AssertSkipNonceEncoded(skipNonce, "skip-nonce attribute encoding");

    SignedTransaction integrator = CreateTestSigner(1_784_267_548_433).SignCreateOrder(
        order,
        42,
        new L2TxAttributes { IntegratorAccountIndex = 12_345, IntegratorTakerFee = 400, IntegratorMakerFee = 200 });
    AssertEqual(
        "c3023ce4c0cd19e19c3129358e67b71ef44a89b82c58fb06cb0a166ba2d40928fcbe9cfb6dda515b",
        integrator.TransactionHash,
        "integrator aggregated hash");
    using (JsonDocument payload = JsonDocument.Parse(integrator.TransactionInfo))
    {
        JsonElement attributes = payload.RootElement.GetProperty("L2TxAttributes");
        AssertEqual(12_345L, attributes.GetProperty("1").GetInt64(), "integrator index attribute encoding");
        AssertEqual(400L, attributes.GetProperty("2").GetInt64(), "integrator taker-fee attribute encoding");
        AssertEqual(200L, attributes.GetProperty("3").GetInt64(), "integrator maker-fee attribute encoding");
    }

    SignedTransaction selfTrade = CreateTestSigner(1_784_267_548_436).SignModifyOrder(
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
    using (JsonDocument payload = JsonDocument.Parse(selfTrade.TransactionInfo))
    {
        JsonElement attributes = payload.RootElement.GetProperty("L2TxAttributes");
        AssertEqual(2L, attributes.GetProperty("6").GetInt64(), "self-trade behavior attribute encoding");
        AssertEqual(1L, attributes.GetProperty("7").GetInt64(), "self-trade equality attribute encoding");
    }

    ModifyOrderRequest modify = new(7, 281_474_976_710_700, 10, 1_000_000, 0);
    SignedTransaction orderVersion = CreateTestSigner(1_784_267_548_436).SignModifyOrder(modify, 45, new L2TxAttributes { OrderVersion = 100 });
    AssertEqual(
        "3acc7977b2904e6ceae8122590bdf7e34b11f2edcb2ec6cd46dabb85ae3019e39510e53f918ed855",
        orderVersion.TransactionHash,
        "order-version aggregated hash");
    using (JsonDocument payload = JsonDocument.Parse(orderVersion.TransactionInfo))
    {
        AssertEqual(100L, payload.RootElement.GetProperty("L2TxAttributes").GetProperty("8").GetInt64(), "order-version attribute encoding");
    }

    SignedTransaction orderVersionSkipNonce = CreateTestSigner(1_784_267_548_436).SignModifyOrder(modify, 45, new L2TxAttributes { SkipNonce = 1, OrderVersion = 100 });
    AssertEqual(
        "74968c2fd57ea8a5f2a98b4b877c27e048084fb91516c455aa61b660935fdb772fee30c0cbe72ba0",
        orderVersionSkipNonce.TransactionHash,
        "order-version with skip-nonce aggregated hash");
    AssertSkipNonceEncoded(orderVersionSkipNonce, "skip-nonce beside order-version encoding");

    SignedTransaction maxOrderVersion = CreateTestSigner(1_784_267_548_436).SignModifyOrder(modify, 45, new L2TxAttributes { OrderVersion = ExchangeConstants.MaxTimestampMilliseconds });
    AssertEqual(
        "a427c0259f3b78c67daf4ec75f02be867ee246c0b2c54398b14e57d788506c0f62ae1bef9d6b3c0e",
        maxOrderVersion.TransactionHash,
        "maximum order-version aggregated hash");

    // Attribute wiring on the remaining four transaction types, each pinned by a Go vector.
    // The hash covers the attribute map independently of the payload, so the JSON encoding
    // is asserted separately to catch a payload that drops the attributes.
    SignedTransaction cancelSkipNonce = CreateTestSigner(1_784_267_548_434).SignCancelOrder(7, 281_474_976_710_700, 43, skipNonceAttributes);
    AssertEqual(
        "1e883b2bb635024d37dd6aba1521665c771c65fef2c68da69d21592e4533172373262afe8b631ffd",
        cancelSkipNonce.TransactionHash,
        "cancel skip-nonce aggregated hash");
    AssertSkipNonceEncoded(cancelSkipNonce, "cancel skip-nonce attribute encoding");

    SignedTransaction transferSkipNonce = CreateTestSigner(1_784_267_548_435).SignTransfer(new TransferRequest(2, 1, 0, 1, 4_294_967_299, 17, VectorMemoHex), 44, skipNonceAttributes);
    AssertEqual(
        "f9d1e3e0c6ae81a1dc3b7ce4307a43ef6c340e1fa1e0b66296e7eb28745d42e340fd4b3d774f12cd",
        transferSkipNonce.TransactionHash,
        "transfer skip-nonce aggregated hash");
    AssertSkipNonceEncoded(transferSkipNonce, "transfer skip-nonce attribute encoding");

    SignedTransaction leverageSkipNonce = CreateTestSigner(1_784_267_548_437).SignUpdateLeverage(7, 500, 1, 46, skipNonceAttributes);
    AssertEqual(
        "fa27dfb891e24df40d095ff4c125fd1713911f84f9dd32229f8bbc2e75456430cadc0c6879449b0d",
        leverageSkipNonce.TransactionHash,
        "leverage skip-nonce aggregated hash");
    AssertSkipNonceEncoded(leverageSkipNonce, "leverage skip-nonce attribute encoding");

    SignedTransaction approveSkipNonce = CreateTestSigner(1_784_267_548_438).SignApproveIntegrator(new ApproveIntegratorRequest(12_345, 100, 50, 100, 50, 1_999_999_999_999), 47, skipNonceAttributes);
    AssertEqual(
        "dd850519104333fa066cbcad17957cb45b52fbe290f494f50f09655e3077d0ae7b2a8330c6019242",
        approveSkipNonce.TransactionHash,
        "approve skip-nonce aggregated hash");
    AssertSkipNonceEncoded(approveSkipNonce, "approve skip-nonce attribute encoding");

    return Task.CompletedTask;
}

static Task TestMarketOrderHashAsync()
{
    SignedTransaction market = CreateTestSigner(1_784_267_548_439).SignCreateOrder(OrderRequest.Create(7, 124, 10, 1_000_000, false, OrderType.Market, OrderTimeInForce.ImmediateOrCancel, false, 0, 0), 49);
    AssertEqual(
        "4448881705390f3aae29a05cc9520738cb5467b3ccd165ba73786927d9b973e8cd1125189c7895f7",
        market.TransactionHash,
        "market-order hash");
    return Task.CompletedTask;
}

static Task TestNilAttributesPreserveHashAsync()
{
    SignedTransaction nilValued = CreateTestSigner(1_784_267_548_433).SignCreateOrder(
        new OrderRequest(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999),
        42,
        new L2TxAttributes { IntegratorAccountIndex = 0, SelfTradeBehaviorMode = 0 });
    AssertEqual(
        "aa8f0203aa47fd2f9c82b85d96a3228b40884ebf2bd7cc6e21668f0a7e5ba16e2b6f3214af822fa6",
        nilValued.TransactionHash,
        "nil-valued attributes hash");
    using JsonDocument payload = JsonDocument.Parse(nilValued.TransactionInfo);
    JsonElement attributes = payload.RootElement.GetProperty("L2TxAttributes");
    AssertEqual(0L, attributes.GetProperty("1").GetInt64(), "nil integrator attribute encoding");
    AssertEqual(0L, attributes.GetProperty("6").GetInt64(), "nil self-trade attribute encoding");

    SignedTransaction nilOrderVersion = CreateTestSigner(1_784_267_548_436).SignModifyOrder(new ModifyOrderRequest(7, 281_474_976_710_700, 10, 1_000_000, 0), 45, new L2TxAttributes { OrderVersion = 0 });
    AssertEqual(
        "eb878794bbe31fd893b06c4054726538b054e62419ba34455f9f1fbaff7205fe537c04d1b0f6376c",
        nilOrderVersion.TransactionHash,
        "nil order-version hash");
    using JsonDocument nilOrderVersionPayload = JsonDocument.Parse(nilOrderVersion.TransactionInfo);
    AssertEqual(0L, nilOrderVersionPayload.RootElement.GetProperty("L2TxAttributes").GetProperty("8").GetInt64(), "nil order-version attribute encoding");
    return Task.CompletedTask;
}

static Task TestAttributeValidationAsync()
{
    LighterSigner signer = CreateTestSigner(1_784_267_548_433);
    OrderRequest order = new(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999);
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
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new L2TxAttributes { IntegratorAccountIndex = -1 }),
        "integrator account index attribute below zero");
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
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new L2TxAttributes { SkipNonce = 0 }),
        "skip nonce zero");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new L2TxAttributes { SkipNonce = 2 }),
        "skip nonce above one");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new L2TxAttributes { SelfTradeBehaviorMode = 4 }),
        "self-trade behavior above reduce");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new L2TxAttributes { SelfTradeEqualityMode = 2 }),
        "self-trade equality above master-account-index");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new L2TxAttributes { IntegratorAccountIndex = 1_000, IntegratorTakerFee = 1_000_001 }),
        "fee above the fee tick");
    AssertThrows<ArgumentOutOfRangeException>(
        () => Sign(new L2TxAttributes { IntegratorAccountIndex = 281_474_976_710_655 }),
        "integrator account index above the maximum");
    ModifyOrderRequest modify = new(7, 281_474_976_710_700, 10, 1_000_000, 0);
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignModifyOrder(modify, 45, new L2TxAttributes { OrderVersion = -1 }),
        "negative order version");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignModifyOrder(modify, 45, new L2TxAttributes { OrderVersion = 1L << 48 }),
        "order version above the maximum");
    AssertThrows<ArgumentException>(
        () => signer.SignModifyOrder(modify, 45, new L2TxAttributes { IntegratorAccountIndex = 1_000, IntegratorTakerFee = 400, IntegratorMakerFee = 200, SkipNonce = 1, OrderVersion = 100 }),
        "order version as a fifth attribute");
    return Task.CompletedTask;
}

static Task TestOrderValidationAsync()
{
    LighterSigner signer = CreateTestSigner(1_784_267_548_433);
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
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.SignCreateOrder(new OrderRequest(7, 125, 10, 100, false, 0, 1, false, 0, -2), 50),
        "negative non-sentinel order expiry");

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
    OrderRequest byteOrder = new(7, 123, 10, 1_000_000, false, 0, 1, false, 0, 1_999_999_999_999);
    OrderRequest enumOrder = OrderRequest.Create(7, 123, 10, 1_000_000, false, OrderType.Limit, OrderTimeInForce.GoodTillTime, false, 0, 1_999_999_999_999);
    AssertEqual(byteOrder, enumOrder, "enum factory equality");
    return Task.CompletedTask;
}

static Task TestTransactionExpiryAsync()
{
    const long nowMilliseconds = 1_784_267_548_433;
    LighterSigner signer = CreateTestSigner(nowMilliseconds);
    signer.TransactionExpiry = TimeSpan.FromMinutes(5);
    SignedTransaction cancel = signer.SignCancelOrder(7, 281_474_976_710_700, 43);
    using (JsonDocument payload = JsonDocument.Parse(cancel.TransactionInfo))
    {
        AssertEqual(
            DateTimeOffset.FromUnixTimeMilliseconds(nowMilliseconds).AddMinutes(5).ToUnixTimeMilliseconds(),
            payload.RootElement.GetProperty("ExpiredAt").GetInt64(),
            "custom transaction expiry");
    }

    AssertEqual(
        LighterSigner.DefaultTransactionExpiry,
        new LighterSigner(TestPrivateKey, 1, 0, 304).TransactionExpiry,
        "default transaction expiry");
    AssertThrows<ArgumentOutOfRangeException>(() => signer.TransactionExpiry = TimeSpan.Zero, "zero transaction expiry");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.TransactionExpiry = TimeSpan.FromSeconds(-1),
        "negative transaction expiry");
    AssertThrows<ArgumentOutOfRangeException>(
        () => signer.TransactionExpiry = TimeSpan.MaxValue,
        "oversized transaction expiry");
    return Task.CompletedTask;
}

static Task TestNegativeAndSpotInputHashesAsync()
{
    // Go hashes signed values via a two's-complement cast, so -1 becomes 2^32 - 2 mod p.
    SignedTransaction negativeIntegrator = CreateTestSigner(1_784_267_548_440).SignApproveIntegrator(new ApproveIntegratorRequest(-1, 100, 50, 100, 50, 1_999_999_999_999), 50);
    AssertEqual(
        "f6988783cbb5c36b1c907d05eba46cf362b3bf84e2b2a5afc3b0c76a111cddc33f64fb18a7193ff0",
        negativeIntegrator.TransactionHash,
        "negative integrator index hash");
    // Go renders the -1 integrator index via two's complement in the L1 body.
    AssertContains("integrator account index: 0xffffffffffffffff", negativeIntegrator.L1SignatureBody!);

    SignedTransaction negativeMarket = CreateTestSigner(1_784_267_548_441).SignUpdateLeverage(-1, 500, 0, 51);
    AssertEqual(
        "99423782871fb3b06e0655cb4f49a3e689daa608ab4091dbf6bbfc35c073489b0f506cb7e05e2f50",
        negativeMarket.TransactionHash,
        "negative leverage market hash");

    SignedTransaction spotCancel = CreateTestSigner(1_784_267_548_442).SignCancelOrder(2048, 281_474_976_710_700, 52);
    AssertEqual(
        "8c9def27ab316cf32a8478353460f5174d67adada531648efff455989ea278e7a7646a7f2c5e85b7",
        spotCancel.TransactionHash,
        "spot-market cancel hash");

    LighterSigner strictSigner = CreateTestSigner(1_784_267_548_442);
    AssertThrows<ArgumentOutOfRangeException>(
        () => strictSigner.SignCancelOrder(7, 1L << 60, 52),
        "cancel index above the maximum");
    AssertThrows<ArgumentOutOfRangeException>(
        () => new LighterSigner(TestPrivateKey, 1, 255, 304),
        "nil api key index");
    AssertThrows<ArgumentOutOfRangeException>(
        () => strictSigner.SignCancelOrder(7, 281_474_976_710_700, -1),
        "negative cancel nonce");
    AssertThrows<ArgumentOutOfRangeException>(
        () => strictSigner.SignTransfer(new TransferRequest(2, 1, 0, 1, 100, 0, new string('0', 64)), -1),
        "negative transfer nonce");
    return Task.CompletedTask;
}

static Task TestL1SignatureAttachmentAsync()
{
    SignedTransaction approval = CreateTestSigner(1_784_267_548_438).SignApproveIntegrator(new ApproveIntegratorRequest(12_345, 100, 50, 100, 50, 1_999_999_999_999), 47);

    // Produced the way the official Python SDK signs approvals: eth_account's sign_message over
    // encode_defunct(text: L1SignatureBody), here with the throwaway key 0x0101...01 (address 0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1).
    const string l1Signature = "0x9a38d1679136f212027f16a3f178d0e67864f77af3065a208307dbc91ff9ce3a58d86a1a7575986cd7c7e505b918560eb4d0ae9d20baa8a74b22d9a2f370ec0b1c";
    SignedTransaction attached = approval.WithL1Signature(l1Signature);
    AssertEqual(approval.TransactionInfo.Replace("\"L1Sig\":\"\"", "\"L1Sig\":\"" + l1Signature + "\"", StringComparison.Ordinal), attached.TransactionInfo, "attached payload differs only in L1Sig");
    AssertEqual(approval.TransactionHash, attached.TransactionHash, "attached transaction hash");
    AssertEqual(approval.TransactionType, attached.TransactionType, "attached transaction type");
    AssertEqual(approval.L1SignatureBody!, attached.L1SignatureBody!, "attached L1 signature body");
    string replacement = "0x" + new string('a', 130);
    AssertEqual(attached.TransactionInfo.Replace(l1Signature, replacement, StringComparison.Ordinal), attached.WithL1Signature(replacement).TransactionInfo, "re-attaching replaces the previous L1Sig");
    using (JsonDocument payload = JsonDocument.Parse(attached.TransactionInfo))
    {
        AssertEqual(l1Signature, payload.RootElement.GetProperty("L1Sig").GetString()!, "attached L1 signature encoding");
        AssertEqual(12_345L, payload.RootElement.GetProperty("IntegratorAccountIndex").GetInt64(), "attached payload integrator");
    }

    // Transfer payloads carry L1Sig too, so a transfer body signed elsewhere attaches the same way.
    SignedTransaction transfer = CreateTestSigner(1_784_267_548_435).SignTransfer(new TransferRequest(2, 1, 0, 1, 4_294_967_299, 17, VectorMemoHex), 44).WithL1Signature(l1Signature);
    using (JsonDocument payload = JsonDocument.Parse(transfer.TransactionInfo))
    {
        AssertEqual(l1Signature, payload.RootElement.GetProperty("L1Sig").GetString()!, "attached transfer L1 signature encoding");
    }

    AssertThrows<ArgumentNullException>(() => approval.WithL1Signature(null!), "null L1 signature");
    AssertThrows<ArgumentException>(() => approval.WithL1Signature(l1Signature[2..]), "L1 signature without the 0x prefix");
    AssertThrows<ArgumentException>(() => approval.WithL1Signature(l1Signature[..130]), "L1 signature shorter than 65 bytes");
    AssertThrows<ArgumentException>(() => approval.WithL1Signature("0x" + new string('z', 130)), "L1 signature with non-hex characters");
    AssertThrows<InvalidOperationException>(() => CreateTestSigner(1_784_267_548_434).SignCancelOrder(7, 281_474_976_710_700, 43).WithL1Signature(l1Signature), "L1 signature on a transaction without L1Sig");
    return Task.CompletedTask;
}

static Task TestPublicSurfaceAsync()
{
    string[] expected =
    [
        "Lighter.Signer.LighterSigner",
        "Lighter.Signer.Transactions.ApproveIntegratorRequest",
        "Lighter.Signer.Transactions.ExchangeConstants",
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
    ];
    string[] actual = typeof(LighterSigner).Assembly.GetExportedTypes().Select(type => type.FullName!).Order(StringComparer.Ordinal).ToArray();

    AssertSequenceEqual(expected, actual, "public signer API surface");
    return Task.CompletedTask;
}

static async Task TestRestWireContractAsync()
{
    ContractHandler handler = new();
    using HttpClient httpClient = new(handler);
    EndpointProfile profile = new("test", new Uri("https://lighter.invalid/"), 304);
    await using LighterApiClient api = new(profile, httpClient);
    SignedTransaction transaction = new(14, "{\"AccountIndex\":1}", "hash");
    SendTransactionResponse response = await api.SendTransactionAsync(transaction, CancellationToken.None);
    AssertEqual(200, response.Code, "sendTx response");
    OrdersResponse orders = await api.GetOpenOrdersAsync(1, "auth-token", CancellationToken.None);
    AssertEqual(0, orders.Orders.Count, "open-order response");
    AssertEqual(true, handler.SawFormContract, "sendTx form contract");
    AssertEqual(true, handler.SawAuthorizationHeader, "active-order auth contract");
}

static async Task TestRestFailureAsync()
{
    using HttpClient httpClient = new(new RejectionHandler());
    EndpointProfile profile = new("test", new Uri("https://lighter.invalid/"), 304);
    await using LighterApiClient api = new(profile, httpClient);
    SignedTransaction transaction = new(14, "{\"AccountIndex\":1}", "hash");

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
    FixedTimeProvider clock = new(DateTimeOffset.FromUnixTimeMilliseconds(1_784_267_557_433));
    ApiCredentials credentials = new("unused", TestPrivateKey, 987_654, "unused", 13);
    LighterSigner signer = new(TestPrivateKey, 987_654, 13, 304, clock);
    StatefulFakeExchange fakeExchange = new();
    using StringWriter output = new(System.Globalization.CultureInfo.InvariantCulture);
    TradingWorkflow workflow = new(fakeExchange, credentials, signer, output, clock, (_, _) => Task.CompletedTask);

    await workflow.RunAsync(CancellationToken.None);
    string text = output.ToString();
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

static LighterSigner CreateTestSigner(long unixTimeMilliseconds) => new(TestPrivateKey, 1, 0, 304, new FixedTimeProvider(DateTimeOffset.FromUnixTimeMilliseconds(unixTimeMilliseconds)));

static void AssertSkipNonceEncoded(SignedTransaction transaction, string description)
{
    using JsonDocument payload = JsonDocument.Parse(transaction.TransactionInfo);
    AssertEqual(1L, payload.RootElement.GetProperty("L2TxAttributes").GetProperty("4").GetInt64(), description);
}

static Scalar ScalarFromLimbs(params ulong[] limbs)
{
    if (limbs.Length != 5)
        throw new ArgumentException("Exactly five limbs are required.", nameof(limbs));

    byte[] bytes = new byte[40];
    for (int index = 0; index < limbs.Length; index++)
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(index * 8, 8), limbs[index]);

    return new Scalar(new BigInteger(bytes, isUnsigned: true, isBigEndian: false));
}

static void AssertEqual<T>(T expected, T actual, string description) where T : notnull
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException($"{description}: expected {expected}, received {actual}");
}

static void AssertSequenceEqual<T>(IEnumerable<T> expected, IEnumerable<T> actual, string description) where T : notnull
{
    T[] expectedArray = expected.ToArray();
    T[] actualArray = actual.ToArray();
    if (!expectedArray.SequenceEqual(actualArray))
        throw new InvalidOperationException($"{description} did not match. Expected [{string.Join(',', expectedArray)}], actual [{string.Join(',', actualArray)}].");
}

static void AssertThrows<TException>(Action action, string description) where TException : Exception
{
    try
    {
        action();
    }
    catch (TException exception) when (exception.GetType() == typeof(TException))
    {
        return;
    }
    catch (Exception exception)
    {
        throw new InvalidOperationException($"{description}: threw {exception.GetType().Name} instead of exactly {typeof(TException).Name}");
    }

    throw new InvalidOperationException($"{description}: no exception was thrown");
}

static void AssertContains(string expected, string actual)
{
    if (!actual.Contains(expected, StringComparison.Ordinal))
        throw new InvalidOperationException($"Output did not contain: {expected}");
}

static void AssertDoesNotContain(string unexpected, string actual)
{
    if (actual.Contains(unexpected, StringComparison.Ordinal))
        throw new InvalidOperationException($"Output contained sensitive value marker: {unexpected}");
}

sealed class FixedTimeProvider(DateTimeOffset value) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => value;
}

sealed class ContractHandler : HttpMessageHandler
{
    public bool SawFormContract { get; private set; }

    public bool SawAuthorizationHeader { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri!.AbsolutePath.EndsWith("/sendTx", StringComparison.Ordinal))
        {
            string body = await request.Content!.ReadAsStringAsync(cancellationToken);
            SawFormContract = request.Content.Headers.ContentType?.MediaType == "application/x-www-form-urlencoded" &&
                              body.Contains("tx_type=14", StringComparison.Ordinal) &&
                              body.Contains("tx_info=", StringComparison.Ordinal);
            return Json("{\"code\":200,\"tx_hash\":\"hash\",\"predicted_execution_time_ms\":1}");
        }

        if (request.RequestUri.AbsolutePath.EndsWith("/accountActiveOrders", StringComparison.Ordinal))
        {
            SawAuthorizationHeader = request.Headers.TryGetValues("authorization", out IEnumerable<string>? values) &&
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
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
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

    public Task<OrdersResponse> GetOpenOrdersAsync(long accountIndex, string authToken, CancellationToken cancellationToken) =>
        Task.FromResult(new OrdersResponse
        {
            Code = 200,
            Orders = _openOrder is null ? [] : [_openOrder],
        });

    public Task<SendTransactionResponse> SendTransactionAsync(SignedTransaction transaction, CancellationToken cancellationToken)
    {
        using JsonDocument document = JsonDocument.Parse(transaction.TransactionInfo);
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
