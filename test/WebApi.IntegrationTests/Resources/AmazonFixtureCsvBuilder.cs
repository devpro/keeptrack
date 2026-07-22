using System.Text;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Builds a small, synthetic Amazon order-history CSV for tests - never use a real personal export as a
/// test fixture (same rule as <see cref="TvTimeFixtureZipBuilder"/>). Amazon's export has no category
/// column, so the Movie/TvShow/VideoGame rows below are just ordinary non-ISBN order lines - the test
/// itself is what assigns their media type at commit time, exactly like a real user would in the review UI.
/// </summary>
internal static class AmazonFixtureCsvBuilder
{
    // Deliberately namespaced "Amazon Import" (not the generic "Keeptrack Integration Test X" TvTimeFixtureZipBuilder
    // uses) - MovieTitle once collided exactly with TvTimeFixtureZipBuilder.MovieTitle in the shared test database,
    // which made TvTimeImportResourceTest's title-matching pick up this fixture's leftover/concurrent movie and
    // report 0 created instead of 1. Keep every title here distinct from every other fixture's, not just internally
    // consistent.
    public const string BookTitle = "Keeptrack Amazon Import Test Book";

    /// <summary>A real, checksum-valid ISBN-10 - exercises the "looks like a book" heuristic honestly.</summary>
    public const string BookIsbn = "0552177571";

    public const string BookOrderId = "999-1111111-1111111";

    public const string NonBookTitle = "Keeptrack Amazon Import Test Gadget";
    private const string NonBookAsin = "B000000001";
    private const string NonBookOrderId = "999-2222222-2222222";

    public const string MovieTitle = "Keeptrack Amazon Import Test Movie";
    private const string MovieAsin = "B000000002";
    public const string MovieOrderId = "999-3333333-3333333";

    public const string TvShowTitle = "Keeptrack Amazon Import Test TV Show";
    private const string TvShowAsin = "B000000003";
    public const string TvShowOrderId = "999-4444444-4444444";

    public const string VideoGameTitle = "Keeptrack Amazon Import Test Video Game";
    private const string VideoGameAsin = "B000000004";
    public const string VideoGameOrderId = "999-5555555-5555555";

    public const string GearTitle = "Keeptrack Amazon Import Test Gear";
    private const string GearAsin = "B000000005";
    public const string GearOrderId = "999-8888888-8888888";

    public const string CollectibleTitle = "Keeptrack Amazon Import Test Collectible";
    private const string CollectibleAsin = "B000000006";
    public const string CollectibleOrderId = "999-9999999-9999999";

    public static byte[] Build()
    {
        var csv = $"""
                   ASIN,Order Date,Order ID,Product Name,Product Condition,Total Amount,Website
                   {BookIsbn},2024-01-24T09:01:58Z,{BookOrderId},{BookTitle},New,10.49,Amazon.fr
                   {NonBookAsin},2020-06-13T21:11:47Z,{NonBookOrderId},{NonBookTitle},New,14.99,Amazon.fr
                   {MovieAsin},2019-05-01T10:00:00Z,{MovieOrderId},{MovieTitle},New,12.99,Amazon.fr
                   {TvShowAsin},2018-03-15T10:00:00Z,{TvShowOrderId},{TvShowTitle},New,29.99,Amazon.fr
                   {VideoGameAsin},2021-07-20T10:00:00Z,{VideoGameOrderId},{VideoGameTitle},New,49.99,Amazon.fr
                   {GearAsin},2022-02-10T10:00:00Z,{GearOrderId},{GearTitle},New,89.99,Amazon.fr
                   {CollectibleAsin},2023-11-05T10:00:00Z,{CollectibleOrderId},{CollectibleTitle},New,39.99,Amazon.fr

                   """;
        return Encoding.UTF8.GetBytes(csv);
    }
}
