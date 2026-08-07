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

static Task TestPublicSurfaceAsync()
{
    var expected = new[]
    {
        "Lighter.Signer.LighterSigner",
        "Lighter.Signer.Transactions.OrderRequest",
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
