using System.Collections.Generic;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class AmazonBookImportMergeServiceTest
{
    private const string OwnerId = "owner-1";

    private static BookModel Book(string title, params OwnedVersionModel[] ownedVersions) =>
        new() { Id = title, OwnerId = OwnerId, Title = title, Author = string.Empty, OwnedVersions = [.. ownedVersions] };

    private static AmazonBookImportRequestItem Item(string title, string? reference = null) => new()
    {
        Title = title,
        OwnedVersion = new OwnedVersionModel { Reference = reference }
    };

    [Fact]
    public void ComputeCommitPlan_CreatesANewBook_WhenNoExistingBookMatchesTheTitle()
    {
        var plan = AmazonBookImportMergeService.ComputeCommitPlan(OwnerId, [], [Item("The Secret")]);

        plan.BooksToCreate.Should().ContainSingle();
        plan.BooksToCreate[0].Title.Should().Be("The Secret");
        plan.BooksToCreate[0].Author.Should().Be(string.Empty);
        plan.BooksToCreate[0].OwnedVersions.Should().ContainSingle();
        plan.BooksToUpdate.Should().BeEmpty();
        plan.OwnedVersionsAdded.Should().Be(1);
    }

    [Fact]
    public void ComputeCommitPlan_MergesIntoAnExistingBook_WhenTheNormalizedTitleMatches()
    {
        var existing = Book("  Some Book  ");

        var plan = AmazonBookImportMergeService.ComputeCommitPlan(OwnerId, [existing], [Item("some book")]);

        plan.BooksToCreate.Should().BeEmpty();
        plan.BooksToUpdate.Should().ContainSingle().Which.Should().BeSameAs(existing);
        existing.OwnedVersions.Should().ContainSingle();
        plan.OwnedVersionsAdded.Should().Be(1);
    }

    [Fact]
    public void ComputeCommitPlan_MergesTwoSelectedRowsSharingATitle_IntoOneNewBook()
    {
        var plan = AmazonBookImportMergeService.ComputeCommitPlan(OwnerId, [], [Item("Duplicate Title"), Item("duplicate title")]);

        plan.BooksToCreate.Should().ContainSingle();
        plan.BooksToCreate[0].OwnedVersions.Should().HaveCount(2);
        plan.BooksToUpdate.Should().BeEmpty();
        plan.OwnedVersionsAdded.Should().Be(2);
    }

    [Fact]
    public void FindImportedOrderIds_ReturnsOnlyOrderIdsFormattedByFormatOrderReference()
    {
        var existingBooks = new List<BookModel>
        {
            Book("Book A", new OwnedVersionModel { Reference = AmazonBookImportMergeService.FormatOrderReference("405-1111111-1111111") }),
            Book("Book B", new OwnedVersionModel { Reference = "Bought at a flea market" }),
            Book("Book C", new OwnedVersionModel { Reference = null })
        };

        var result = AmazonBookImportMergeService.FindImportedOrderIds(existingBooks);

        result.Should().BeEquivalentTo(["405-1111111-1111111"]);
    }
}
