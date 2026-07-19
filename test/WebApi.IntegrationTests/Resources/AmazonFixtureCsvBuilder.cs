using System.Text;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Builds a small, synthetic Amazon order-history CSV for tests - never use a real personal export as a
/// test fixture (same rule as <see cref="TvTimeFixtureZipBuilder"/>).
/// </summary>
internal static class AmazonFixtureCsvBuilder
{
    public const string BookTitle = "Keeptrack Integration Test Book";

    /// <summary>A real, checksum-valid ISBN-10 - exercises the "looks like a book" heuristic honestly.</summary>
    public const string BookIsbn = "0552177571";

    public const string BookOrderId = "999-1111111-1111111";

    public const string NonBookTitle = "Keeptrack Integration Test Gadget";
    private const string NonBookAsin = "B000000001";
    private const string NonBookOrderId = "999-2222222-2222222";

    public static byte[] Build()
    {
        var csv = $"""
                   ASIN,Order Date,Order ID,Product Name,Product Condition,Total Amount,Website
                   {BookIsbn},2024-01-24T09:01:58Z,{BookOrderId},{BookTitle},New,10.49,Amazon.fr
                   {NonBookAsin},2020-06-13T21:11:47Z,{NonBookOrderId},{NonBookTitle},New,14.99,Amazon.fr

                   """;
        return Encoding.UTF8.GetBytes(csv);
    }
}
