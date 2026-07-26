using System.Collections.Generic;
using System.IO;
using System.Text;
using AwesomeAssertions;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class GenericVideoGameImportServiceTest
{
    private static Stream ToStream(string csv) => new MemoryStream(Encoding.UTF8.GetBytes(csv));

    private const string Csv = """
                               Transaction Date,Game Name,Product Name,Platform,Vendor,Transaction Id,Order Id,Final Price (€)
                               2019-08-02,Grand Theft Auto V (PS4),Grand Theft Auto V : Édition Premium,PS4,PlayStation Store,148888333444,70557088055,14.99
                               2021-03-15,Returnal,Returnal,PS5,PlayStation Store,200000000001,80000000001,79.99
                               """;

    [Fact]
    public void BuildPreview_StripsTheTrailingPlatformSuffixFromTheTitle()
    {
        var result = GenericVideoGameImportService.BuildPreview(ToStream(Csv), new HashSet<string>());

        result[0].Title.Should().Be("Grand Theft Auto V");
    }

    [Fact]
    public void BuildPreview_LeavesATitleWithNoMatchingPlatformSuffixUnchanged()
    {
        var result = GenericVideoGameImportService.BuildPreview(ToStream(Csv), new HashSet<string>());

        result[1].Title.Should().Be("Returnal");
    }

    [Fact]
    public void BuildPreview_CarriesTheProductNamePlatformAndVendorThrough()
    {
        var result = GenericVideoGameImportService.BuildPreview(ToStream(Csv), new HashSet<string>());

        result[0].ProductName.Should().Be("Grand Theft Auto V : Édition Premium");
        result[0].Platform.Should().Be("PS4");
        result[0].Vendor.Should().Be("PlayStation Store");
    }

    [Fact]
    public void BuildPreview_ParsesThePriceAndTransactionDate()
    {
        var result = GenericVideoGameImportService.BuildPreview(ToStream(Csv), new HashSet<string>());

        result[0].Price.Should().Be(14.99m);
        result[0].TransactionDate.Should().Be(new System.DateOnly(2019, 8, 2));
    }

    [Fact]
    public void BuildPreview_LeavesPriceNull_WhenTheColumnIsBlank()
    {
        const string csv = """
                            Transaction Date,Game Name,Product Name,Platform,Vendor,Transaction Id,Order Id,Final Price (€)
                            2019-08-02,Some Game,Some Game,PS4,PlayStation Store,148888333444,70557088055,
                            """;

        var result = GenericVideoGameImportService.BuildPreview(ToStream(csv), new HashSet<string>());

        result[0].Price.Should().BeNull();
    }

    [Fact]
    public void BuildPreview_FlagsARowWhoseTransactionOrderAndProductAreAlreadyImported()
    {
        var alreadyImported = new HashSet<string>
        {
            GenericVideoGameImportService.FormatReference("148888333444", "70557088055", "Grand Theft Auto V : Édition Premium", "Grand Theft Auto V (PS4)")
        };

        var result = GenericVideoGameImportService.BuildPreview(ToStream(Csv), alreadyImported);

        result[0].AlreadyImported.Should().BeTrue();
        result[1].AlreadyImported.Should().BeFalse();
    }

    [Fact]
    public void FormatReference_IncludesTheOrderIdTransactionIdAndProductName()
    {
        GenericVideoGameImportService.FormatReference("148888333444", "70557088055", "Grand Theft Auto V : Édition Premium", "Grand Theft Auto V (PS4)")
            .Should().Be("Order 70557088055 (transaction 148888333444) - Grand Theft Auto V : Édition Premium");
    }

    [Fact]
    public void FormatReference_FallsBackToTheTitle_WhenProductNameIsBlank()
    {
        GenericVideoGameImportService.FormatReference("148888333444", "70557088055", null, "Grand Theft Auto V (PS4)")
            .Should().Be("Order 70557088055 (transaction 148888333444) - Grand Theft Auto V (PS4)");
    }

    [Fact]
    public void FormatReference_Disambiguates_WhenTwoLinesShareTheSameTransactionAndOrder()
    {
        // reproduces a real bug: a single PSN transaction can bundle several different DLC packs under the
        // exact same Transaction Id/Order Id, distinguishable only by Product Name
        var first = GenericVideoGameImportService.FormatReference("786966888755333", "399229990555", "FAR CRY 4 Vallée des Yétis", "FAR CRY 4");
        var second = GenericVideoGameImportService.FormatReference("786966888755333", "399229990555", "Pack Hurk Deluxe", "FAR CRY 4");

        first.Should().NotBe(second);
    }

    [Fact]
    public void BuildProvenanceNotes_IncludesTheVendorAndSourceTitle()
    {
        GenericVideoGameImportService.BuildProvenanceNotes("PlayStation Store", "Grand Theft Auto V (PS4)")
            .Should().Be("Title from PlayStation Store: Grand Theft Auto V (PS4)");
    }

    [Fact]
    public void CleanTitle_IsCaseInsensitiveOnThePlatformSuffix()
    {
        GenericVideoGameImportService.CleanTitle("Returnal (ps5)", "PS5").Should().Be("Returnal");
    }
}
