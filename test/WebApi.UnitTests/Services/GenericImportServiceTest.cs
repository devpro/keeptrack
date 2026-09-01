using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class GenericImportServiceTest
{
    private static MemoryStream ToStream(string csv) => new(Encoding.UTF8.GetBytes(csv));

    // The header shape from a real Rakuten export the user reshapes in a spreadsheet - exercises every canonical
    // alias at once (Product Name -> Title, ASIN -> Product Id, Product Condition -> Condition, Total Amount ->
    // Price). Vendor (the store name -> the copy's Vendor field) and Website (the item URL -> the copy's
    // Reference) are two separate columns feeding two different fields.
    private const string RakutenCsv = """
                                      Order Date,Order ID,ASIN,Product Name,Product Condition,Total Amount,Vendor,Website,Type,Platform,Author
                                      2021-06-12,ORD-1,ASIN-1,The Left Hand of Darkness,Used - Good,12.50,Rakuten,https://fr.shopping.rakuten.com/a,Book,,Ursula K. Le Guin
                                      2022-01-05,ORD-2,ASIN-2,Elden Ring,New,49.99,Rakuten,https://fr.shopping.rakuten.com/b,VideoGame,PS5,
                                      """;

    [Fact]
    public void BuildPreview_ResolvesEveryCanonicalColumnAliasFromARealRakutenHeader()
    {
        var rows = GenericImportService.BuildPreview(ToStream(RakutenCsv), new HashSet<string>());

        var book = rows[0];
        book.Title.Should().Be("The Left Hand of Darkness");
        book.SuggestedMediaType.Should().Be(ImportMediaType.Book);
        book.OrderId.Should().Be("ORD-1");
        book.ProductId.Should().Be("ASIN-1");
        book.Condition.Should().Be("Used - Good");
        book.Price.Should().Be(12.50m);
        book.Vendor.Should().Be("Rakuten");
        book.Website.Should().Be("https://fr.shopping.rakuten.com/a");
        book.Author.Should().Be("Ursula K. Le Guin");
        book.OrderDate.Should().Be(new DateOnly(2021, 6, 12));
    }

    [Fact]
    public void BuildPreview_ReadsTheWebsiteColumnIntoItsOwnFieldNotTheVendor()
    {
        // Website is a separate column feeding the copy's Reference, never the Vendor field.
        const string csv = """
                           Title,Type,Website
                           A Book,Book,https://example.com/item
                           """;

        var rows = GenericImportService.BuildPreview(ToStream(csv), new HashSet<string>());

        rows[0].Vendor.Should().BeNull();
        rows[0].Website.Should().Be("https://example.com/item");
    }

    [Theory]
    [InlineData("Vendor")]
    [InlineData("Store")]
    public void BuildPreview_ReadsTheVendorFromAnyOfItsAcceptedColumnNames(string vendorHeader)
    {
        var csv = $"""
                  Title,Type,{vendorHeader}
                  A Book,Book,Rakuten
                  """;

        GenericImportService.BuildPreview(ToStream(csv), new HashSet<string>())[0].Vendor.Should().Be("Rakuten");
    }

    [Fact]
    public void BuildPreview_ReadsPlatformAndTypeForAVideoGameRow()
    {
        var rows = GenericImportService.BuildPreview(ToStream(RakutenCsv), new HashSet<string>());

        rows[1].SuggestedMediaType.Should().Be(ImportMediaType.VideoGame);
        rows[1].Platform.Should().Be("PS5");
    }

    [Theory]
    [InlineData("Book", ImportMediaType.Book)]
    [InlineData("books", ImportMediaType.Book)]
    [InlineData("Movie", ImportMediaType.Movie)]
    [InlineData("Film", ImportMediaType.Movie)]
    [InlineData("TV Show", ImportMediaType.TvShow)]
    [InlineData("tvshow", ImportMediaType.TvShow)]
    [InlineData("series", ImportMediaType.TvShow)]
    [InlineData("Video Game", ImportMediaType.VideoGame)]
    [InlineData("game", ImportMediaType.VideoGame)]
    [InlineData("Gear", ImportMediaType.Gear)]
    [InlineData("Collectible", ImportMediaType.Collectible)]
    public void ParseMediaType_MapsTheNaturalSpellingsAUserWouldType(string raw, ImportMediaType expected)
    {
        GenericImportService.ParseMediaType(raw).Should().Be(expected);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("widget")]
    public void ParseMediaType_ReturnsNull_ForBlankOrUnrecognizedValues(string raw)
    {
        GenericImportService.ParseMediaType(raw).Should().BeNull();
    }

    [Fact]
    public void BuildPreview_LeavesSuggestedMediaTypeNull_WhenTheTypeColumnIsAbsentEntirely()
    {
        const string csv = """
                           Title,Vendor
                           Some Item,Rakuten
                           """;

        var rows = GenericImportService.BuildPreview(ToStream(csv), new HashSet<string>());

        rows[0].Title.Should().Be("Some Item");
        rows[0].SuggestedMediaType.Should().BeNull();
    }

    [Fact]
    public void BuildPreview_ParsesADigitalCopyFromTheCopyColumnAndCurrencyDecoratedPrice()
    {
        const string csv = """
                           Title,Type,Copy,Price,Year
                           A Digital Movie,Movie,Digital,€9.99,2018
                           """;

        var rows = GenericImportService.BuildPreview(ToStream(csv), new HashSet<string>());

        rows[0].CopyType.Should().Be(CopyType.Digital);
        rows[0].Price.Should().Be(9.99m);
        rows[0].Year.Should().Be(2018);
    }

    [Fact]
    public void BuildPreview_DefaultsCopyTypeToPhysical_WhenNoCopyColumnIsPresent()
    {
        const string csv = """
                           Title,Type
                           A Physical Book,Book
                           """;

        GenericImportService.BuildPreview(ToStream(csv), new HashSet<string>())[0].CopyType.Should().Be(CopyType.Physical);
    }

    [Fact]
    public void FormatReference_IncludesTheWebsiteLabelOrderIdAndProductId()
    {
        GenericImportService.FormatReference("https://rakuten.fr/a", "ORD-1", "ASIN-1", "The Left Hand of Darkness")
            .Should().Be("https://rakuten.fr/a order ORD-1 (ASIN-1)");
    }

    [Fact]
    public void FormatReference_FallsBackToTheTitle_WhenProductIdIsBlank()
    {
        GenericImportService.FormatReference("https://rakuten.fr/a", "ORD-1", null, "The Left Hand of Darkness")
            .Should().Be("https://rakuten.fr/a order ORD-1 (The Left Hand of Darkness)");
    }

    [Fact]
    public void FormatReference_Disambiguates_WhenTwoLinesShareOneOrderButDifferentProducts()
    {
        // A non-unique Website label is harmless: order id + product id are what disambiguate.
        var first = GenericImportService.FormatReference("https://rakuten.fr", "ORD-9", "ASIN-A", "Bundle");
        var second = GenericImportService.FormatReference("https://rakuten.fr", "ORD-9", "ASIN-B", "Bundle");

        first.Should().NotBe(second);
    }

    [Fact]
    public void BuildPreview_BuildsTheDedupReferenceFromTheWebsiteColumnNotTheVendor()
    {
        // The reference (and dedup key) uses the Website label, independent of the Vendor field.
        var keyedOnWebsite = new HashSet<string>
        {
            GenericImportService.FormatReference("https://fr.shopping.rakuten.com/a", "ORD-1", "ASIN-1", "The Left Hand of Darkness")
        };
        GenericImportService.BuildPreview(ToStream(RakutenCsv), keyedOnWebsite)[0].AlreadyImported.Should().BeTrue();

        var keyedOnVendor = new HashSet<string>
        {
            GenericImportService.FormatReference("Rakuten", "ORD-1", "ASIN-1", "The Left Hand of Darkness")
        };
        GenericImportService.BuildPreview(ToStream(RakutenCsv), keyedOnVendor)[0].AlreadyImported.Should().BeFalse();
    }

    [Fact]
    public void BuildProvenanceNotes_IncludesTheVendorAndSourceTitle()
    {
        GenericImportService.BuildProvenanceNotes("Rakuten", "The Left Hand of Darkness", null)
            .Should().Be("Title from Rakuten: The Left Hand of Darkness");
    }

    [Fact]
    public void BuildProvenanceNotes_AddsAnIsbnLine_ForABook()
    {
        GenericImportService.BuildProvenanceNotes("Rakuten", "The Left Hand of Darkness", "9780441478125")
            .Should().Be("Title from Rakuten: The Left Hand of Darkness\nISBN from Rakuten: 9780441478125");
    }
}
