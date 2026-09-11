namespace Lighter.Signer.Transactions;

public enum OrderType : byte
{
    Limit = 0,
    Market = 1,
    StopLoss = 2,
    StopLossLimit = 3,
    TakeProfit = 4,
    TakeProfitLimit = 5,
    Twap = 6,
}

public enum OrderTimeInForce : byte
{
    ImmediateOrCancel = 0,
    GoodTillTime = 1,
    PostOnly = 2,
}

public enum SelfTradeBehavior : byte
{
    ExpireMaker = 0,
    ExpireTaker = 1,
    CancelBoth = 2,
    Reduce = 3,
}

public enum SelfTradeEquality : byte
{
    AccountIndex = 0,
    MasterAccountIndex = 1,
}

public enum MarginMode : byte
{
    Cross = 0,
    Isolated = 1,
}
