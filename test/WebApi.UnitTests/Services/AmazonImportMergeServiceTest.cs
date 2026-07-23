using AwesomeAssertions;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class AmazonImportMergeServiceTest
{
    private const string SomeOrderId = "405-1111111-1111111";
    private const string SomeAsin = "0552177571";

    [Fact]
    public void FormatOrderReference_IncludesBothTheOrderIdAndTheAsin()
    {
        AmazonImportMergeService.FormatOrderReference(SomeOrderId, SomeAsin).Should().Be($"Amazon order {SomeOrderId} (ASIN {SomeAsin})");
    }

    [Fact]
    public void BuildAmazonProvenanceNotes_IncludesTheIsbnLine_WhenAnIsbnIsGiven()
    {
        AmazonImportMergeService.BuildAmazonProvenanceNotes("The Secret: Jack Reacher, Book 28", "0552177571")
            .Should().Be("Title from Amazon: The Secret: Jack Reacher, Book 28\nISBN from Amazon: 0552177571");
    }

    [Fact]
    public void BuildAmazonProvenanceNotes_OmitsTheIsbnLine_WhenThereIsNoIsbn()
    {
        AmazonImportMergeService.BuildAmazonProvenanceNotes("A Book With No Isbn", null)
            .Should().Be("Title from Amazon: A Book With No Isbn");
    }
}
