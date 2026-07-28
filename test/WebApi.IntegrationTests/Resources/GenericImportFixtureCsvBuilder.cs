using System.Text;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Builds a small, synthetic generic store/CSV import fixture for tests - never use a real personal export as
/// a test fixture (same rule as <see cref="AmazonFixtureCsvBuilder"/>). Uses the exact real-world Rakuten
/// header shape (Product Name, ASIN, Product Condition, Total Amount, Website...) so the test doubles as proof
/// the canonical column aliases resolve against a genuine export header.
/// </summary>
internal static class GenericImportFixtureCsvBuilder
{
    public const string Vendor = "Rakuten";

    public const string BookTitle = "Keeptrack Generic Import Test Book";
    public const string BookAuthor = "Keeptrack Test Author";
    public const string BookOrderId = "GEN-ORD-1";
    public const string BookProductId = "GEN-ASIN-1";
    public const string BookCondition = "Used - Very Good";
    public const string BookWebsite = "https://fr.shopping.rakuten.com/book";

    public const string MovieTitle = "Keeptrack Generic Import Test Movie";
    public const string MovieOrderId = "GEN-ORD-2";
    public const string MovieProductId = "GEN-ASIN-2";

    public const string VideoGameTitle = "Keeptrack Generic Import Test Game";
    public const string VideoGamePlatform = "PS5";
    public const string VideoGameOrderId = "GEN-ORD-3";
    public const string VideoGameProductId = "GEN-ASIN-3";

    public static byte[] Build()
    {
        var csv = $"""
                   Order Date,Order ID,ASIN,Product Name,Product Condition,Total Amount,Vendor,Website,Type,Platform,Author
                   2021-06-12,{BookOrderId},{BookProductId},{BookTitle},{BookCondition},12.50,{Vendor},{BookWebsite},Book,,{BookAuthor}
                   2022-01-05,{MovieOrderId},{MovieProductId},{MovieTitle},New,9.99,{Vendor},,Movie,,
                   2022-03-20,{VideoGameOrderId},{VideoGameProductId},{VideoGameTitle},New,49.99,{Vendor},,VideoGame,{VideoGamePlatform},

                   """;
        return Encoding.UTF8.GetBytes(csv);
    }
}
