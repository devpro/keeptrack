using System.Collections.Generic;
using System.IO;
using System.Text;
using AwesomeAssertions;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class AmazonOrderPreviewServiceTest
{
    private static Stream ToStream(string csv) => new MemoryStream(Encoding.UTF8.GetBytes(csv));

    // The "Ã©" sequence below is deliberately literal (not a copy/paste accident) - it reproduces the real
    // export's mojibake byte-for-byte, confirmed against the raw bytes of a real Amazon order-history CSV.
    private const string Csv = """
                               ASIN,Order Date,Order ID,Product Name,Product Condition,Total Amount,Website
                               0552177571,2024-01-24T09:01:58Z,405-2296545-4493925,"protection d'Ã©crans",New,10.49,Amazon.fr
                               B002KMW6ZI,2010-12-06T09:02:46Z,402-4436663-3305145,Some Gadget,Neuf,'19.16',Amazon.fr
                               """;

    [Fact]
    public void BuildPreview_RepairsMojibakeInTheProductName()
    {
        var result = AmazonOrderPreviewService.BuildPreview(ToStream(Csv), new HashSet<string>());

        result[0].Title.Should().Be("protection d'écrans");
    }

    [Fact]
    public void BuildPreview_DecodesARawNumericHtmlEntityInTheProductName()
    {
        const string csv = """
                            ASIN,Order Date,Order ID,Product Name,Product Condition,Total Amount,Website
                            2811205063,2020-02-02T09:26:31Z,403-0337751-9465130,"Sorceleur, Tome 1: Le Dernier V&#x153;u",New,7.1,Amazon.fr
                            """;

        var result = AmazonOrderPreviewService.BuildPreview(ToStream(csv), new HashSet<string>());

        result[0].Title.Should().Be("Sorceleur, Tome 1: Le Dernier Vœu");
    }

    [Fact]
    public void BuildPreview_FlagsAnIsbn10ShapedAsinAsLikelyABook()
    {
        var result = AmazonOrderPreviewService.BuildPreview(ToStream(Csv), new HashSet<string>());

        result[0].LooksLikeBook.Should().BeTrue();
        result[0].SuggestedIsbn.Should().Be("0552177571");
    }

    [Fact]
    public void BuildPreview_DoesNotFlagANonIsbnAsin()
    {
        var result = AmazonOrderPreviewService.BuildPreview(ToStream(Csv), new HashSet<string>());

        result[1].LooksLikeBook.Should().BeFalse();
        result[1].SuggestedIsbn.Should().BeNull();
    }

    [Fact]
    public void BuildPreview_AcceptsAnXCheckDigitIsbn10()
    {
        const string csv = """
                            ASIN,Order Date,Order ID,Product Name,Product Condition,Total Amount,Website
                            080442957X,2020-01-01T00:00:00Z,111-1111111-1111111,A Book,New,9.99,Amazon.fr
                            """;

        var result = AmazonOrderPreviewService.BuildPreview(ToStream(csv), new HashSet<string>());

        result[0].LooksLikeBook.Should().BeTrue();
    }

    [Fact]
    public void BuildPreview_StripsAmazonsExcelFormulaInjectionApostropheBeforeParsingThePrice()
    {
        var result = AmazonOrderPreviewService.BuildPreview(ToStream(Csv), new HashSet<string>());

        result[1].Price.Should().Be(19.16m);
    }

    [Fact]
    public void BuildPreview_FlagsARowWhoseOrderIdIsAlreadyImported()
    {
        var alreadyImported = new HashSet<string> { "405-2296545-4493925" };

        var result = AmazonOrderPreviewService.BuildPreview(ToStream(Csv), alreadyImported);

        result[0].AlreadyImported.Should().BeTrue();
        result[1].AlreadyImported.Should().BeFalse();
    }
}
