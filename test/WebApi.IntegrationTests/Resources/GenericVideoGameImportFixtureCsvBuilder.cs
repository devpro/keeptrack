using System.Text;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Builds a small, synthetic video game transaction-history CSV for tests - never use a real personal
/// export as a test fixture (same rule as <see cref="AmazonFixtureCsvBuilder"/>).
/// </summary>
internal static class GenericVideoGameImportFixtureCsvBuilder
{
    public const string GameTitle = "Keeptrack Video Game Import Test Game";
    public const string GamePlatform = "PS4";
    public const string GameProductName = "Keeptrack Video Game Import Test Game : Premium Edition";
    public const string GameVendor = "PlayStation Store";
    public const string GameTransactionId = "999888777001";
    public const string GameOrderId = "999888777002";

    public const string SecondGameTitle = "Keeptrack Video Game Import Test Game Two";
    private const string SecondGameTransactionId = "999888777003";
    private const string SecondGameOrderId = "999888777004";

    /// <summary>
    /// Reproduces a real PSN export shape: a single order bundled three different DLC packs for the same
    /// game under one shared Transaction Id/Order Id, distinguishable only by Product Name.
    /// </summary>
    public const string BundleTitle = "Keeptrack Video Game Import Test Bundle Game";
    private const string BundleTransactionId = "999888777005";
    private const string BundleOrderId = "999888777006";
    public const string BundleProductA = "Keeptrack Video Game Import Test Bundle Game - DLC A";
    public const string BundleProductB = "Keeptrack Video Game Import Test Bundle Game - DLC B";
    public const string BundleProductC = "Keeptrack Video Game Import Test Bundle Game - DLC C";

    public static byte[] Build()
    {
        var csv = $"""
                   Transaction Date,Game Name,Product Name,Platform,Vendor,Transaction Id,Order Id,Final Price (€)
                   2019-08-02,{GameTitle} ({GamePlatform}),{GameProductName},{GamePlatform},{GameVendor},{GameTransactionId},{GameOrderId},14.99
                   2021-03-15,{SecondGameTitle},{SecondGameTitle},PS5,{GameVendor},{SecondGameTransactionId},{SecondGameOrderId},59.99
                   2025-11-21,{BundleTitle},{BundleProductA},PS4,{GameVendor},{BundleTransactionId},{BundleOrderId},2.24
                   2025-11-21,{BundleTitle},{BundleProductB},PS4,{GameVendor},{BundleTransactionId},{BundleOrderId},1.12
                   2025-11-21,{BundleTitle},{BundleProductC},PS4,{GameVendor},{BundleTransactionId},{BundleOrderId},1.49

                   """;
        return Encoding.UTF8.GetBytes(csv);
    }
}
