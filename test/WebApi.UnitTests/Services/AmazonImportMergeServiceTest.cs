using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class AmazonImportMergeServiceTest
{
    private const string OwnerId = "owner-1";

    private static BookModel Book(string title, params OwnedVersionModel[] ownedVersions) =>
        new() { Id = title, OwnerId = OwnerId, Title = title, Author = string.Empty, OwnedVersions = [.. ownedVersions] };

    private static VideoGameModel Game(string title, params VideoGamePlatformModel[] platforms) =>
        new() { Id = title, OwnerId = OwnerId, Title = title, Platforms = [.. platforms] };

    private static AmazonOwnedItemImportRequestItem Item(string title, string? reference = null, string? amazonTitle = null, string? isbn = null) => new()
    {
        Title = title,
        AmazonTitle = amazonTitle ?? title,
        Isbn = isbn,
        OwnedVersion = new OwnedVersionModel { Reference = reference }
    };

    /// <summary>Wires up the generic engine for BookModel, the same way <c>AmazonImportController</c> does.</summary>
    private static AmazonImportPlan<BookModel> ComputeBookPlan(IReadOnlyCollection<BookModel> existing, IReadOnlyList<AmazonOwnedItemImportRequestItem> items) =>
        AmazonImportMergeService.ComputeCommitPlan(
            existing, items,
            b => b.Title, b => b.OwnedVersions.Select(v => v.Reference),
            i => i.Title, i => i.OwnedVersion.Reference,
            item => new BookModel
            {
                OwnerId = OwnerId,
                Title = item.Title,
                Author = string.Empty,
                Notes = AmazonImportMergeService.BuildAmazonProvenanceNotes(item.AmazonTitle, item.Isbn),
                OwnedVersions = [item.OwnedVersion]
            },
            (book, item) => book.OwnedVersions.Add(item.OwnedVersion));

    [Fact]
    public void ComputeCommitPlan_CreatesANewBook_WhenNoExistingBookMatchesTheTitle()
    {
        var plan = ComputeBookPlan([], [Item("The Secret")]);

        plan.ItemsToCreate.Should().ContainSingle();
        plan.ItemsToCreate[0].Title.Should().Be("The Secret");
        plan.ItemsToCreate[0].Author.Should().Be(string.Empty);
        plan.ItemsToCreate[0].OwnedVersions.Should().ContainSingle();
        plan.ItemsToUpdate.Should().BeEmpty();
        plan.OwnedCopiesAdded.Should().Be(1);
    }

    [Fact]
    public void ComputeCommitPlan_RecordsAmazonsOriginalTitleAndIsbnInNotes_ForANewlyCreatedBook()
    {
        var item = Item("The Secret", amazonTitle: "The Secret: Jack Reacher, Book 28", isbn: "0552177571");

        var plan = ComputeBookPlan([], [item]);

        plan.ItemsToCreate[0].Notes.Should().Be("Title from Amazon: The Secret: Jack Reacher, Book 28\nISBN from Amazon: 0552177571");
    }

    [Fact]
    public void ComputeCommitPlan_OmitsTheIsbnNoteLine_WhenThereIsNoIsbn()
    {
        var item = Item("A Book With No Isbn", amazonTitle: "A Book With No Isbn");

        var plan = ComputeBookPlan([], [item]);

        plan.ItemsToCreate[0].Notes.Should().Be("Title from Amazon: A Book With No Isbn");
    }

    [Fact]
    public void ComputeCommitPlan_DoesNotTouchNotes_WhenMergingIntoAnExistingBook()
    {
        var existing = Book("Some Book");
        existing.Notes = "My own pre-existing notes";

        var plan = ComputeBookPlan([existing], [Item("some book", amazonTitle: "Some Book (Amazon listing)")]);

        plan.ItemsToCreate.Should().BeEmpty();
        existing.Notes.Should().Be("My own pre-existing notes");
    }

    [Fact]
    public void ComputeCommitPlan_MergesIntoAnExistingBook_WhenTheNormalizedTitleMatches()
    {
        var existing = Book("  Some Book  ");

        var plan = ComputeBookPlan([existing], [Item("some book")]);

        plan.ItemsToCreate.Should().BeEmpty();
        plan.ItemsToUpdate.Should().ContainSingle().Which.Should().BeSameAs(existing);
        existing.OwnedVersions.Should().ContainSingle();
        plan.OwnedCopiesAdded.Should().Be(1);
    }

    [Fact]
    public void ComputeCommitPlan_MergesTwoSelectedRowsSharingATitle_IntoOneNewBook()
    {
        var plan = ComputeBookPlan([], [Item("Duplicate Title"), Item("duplicate title")]);

        plan.ItemsToCreate.Should().ContainSingle();
        plan.ItemsToCreate[0].OwnedVersions.Should().HaveCount(2);
        plan.ItemsToUpdate.Should().BeEmpty();
        plan.OwnedCopiesAdded.Should().Be(2);
    }

    [Fact]
    public void ComputeCommitPlan_SkipsARow_WhenItsOrderReferenceAlreadyExistsOnAnExistingBook()
    {
        // reproduces a real bug: re-running the same commit (or re-importing the same export) created a
        // second owned version for the same order every time, because matching was title-only
        var reference = AmazonImportMergeService.FormatOrderReference("405-1111111-1111111");
        var existing = Book("Some Book", new OwnedVersionModel { Reference = reference });

        var plan = ComputeBookPlan([existing], [Item("Some Book", reference: reference)]);

        plan.ItemsToCreate.Should().BeEmpty();
        plan.ItemsToUpdate.Should().BeEmpty();
        existing.OwnedVersions.Should().ContainSingle();
        plan.OwnedCopiesAdded.Should().Be(0);
        plan.OwnedCopiesSkipped.Should().Be(1);
    }

    [Fact]
    public void ComputeCommitPlan_SkipsARow_WhenItsOrderReferenceMatchesAnExistingBook_EvenUnderADifferentTitleNow()
    {
        // reproduces a real bug: after a book's title was changed (e.g. by reference-data linking) following
        // a first import, re-importing the same order under its original Amazon title no longer matched the
        // existing book by title at all, and created a brand new duplicate record instead
        var reference = AmazonImportMergeService.FormatOrderReference("405-1111111-1111111");
        var existing = Book("The Secret: Jack Reacher, Book 28", new OwnedVersionModel { Reference = reference });
        existing.Title = "No Plan B"; // renamed after the first import, e.g. by reference-data linking

        var plan = ComputeBookPlan([existing], [Item("The Secret: Jack Reacher, Book 28", reference: reference)]);

        plan.ItemsToCreate.Should().BeEmpty();
        plan.ItemsToUpdate.Should().BeEmpty();
        existing.OwnedVersions.Should().ContainSingle();
        plan.OwnedCopiesSkipped.Should().Be(1);
    }

    [Fact]
    public void ComputeCommitPlan_StillMergesASecondCopy_WhenTheOrderReferenceIsGenuinelyDifferent()
    {
        var existing = Book("Some Book", new OwnedVersionModel { Reference = AmazonImportMergeService.FormatOrderReference("405-1111111-1111111") });

        var plan = ComputeBookPlan([existing], [Item("some book", reference: AmazonImportMergeService.FormatOrderReference("405-9999999-9999999"))]);

        plan.ItemsToUpdate.Should().ContainSingle().Which.Should().BeSameAs(existing);
        existing.OwnedVersions.Should().HaveCount(2);
        plan.OwnedCopiesSkipped.Should().Be(0);
    }

    [Fact]
    public void ComputeCommitPlan_WorksUnmodifiedForVideoGames_ViaPlatformsInsteadOfOwnedVersions()
    {
        var item = new AmazonVideoGameImportRequestItem
        {
            Title = "L.A. Noire",
            AmazonTitle = "L.A. Noire",
            Platform = new VideoGamePlatformModel { Platform = "PS3" }
        };

        var plan = AmazonImportMergeService.ComputeCommitPlan(
            new List<VideoGameModel>(), [item],
            g => g.Title, g => g.Platforms.Select(p => p.Reference),
            i => i.Title, i => i.Platform.Reference,
            requestItem => new VideoGameModel { OwnerId = OwnerId, Title = requestItem.Title, Platforms = [requestItem.Platform] },
            (game, requestItem) => game.Platforms.Add(requestItem.Platform));

        plan.ItemsToCreate.Should().ContainSingle();
        plan.ItemsToCreate[0].Platforms.Should().ContainSingle().Which.Platform.Should().Be("PS3");
        plan.OwnedCopiesAdded.Should().Be(1);
    }

    [Fact]
    public void FindImportedOrderIds_ReturnsOnlyOrderIdsFormattedByFormatOrderReference()
    {
        var existingBooks = new List<BookModel>
        {
            Book("Book A", new OwnedVersionModel { Reference = AmazonImportMergeService.FormatOrderReference("405-1111111-1111111") }),
            Book("Book B", new OwnedVersionModel { Reference = "Bought at a flea market" }),
            Book("Book C", new OwnedVersionModel { Reference = null })
        };

        var result = AmazonImportMergeService.FindImportedOrderIds(existingBooks, b => b.OwnedVersions.Select(v => v.Reference));

        result.Should().BeEquivalentTo(["405-1111111-1111111"]);
    }

    [Fact]
    public void FindImportedOrderIds_WorksAcrossVideoGamePlatformsToo()
    {
        var existingGames = new List<VideoGameModel>
        {
            Game("Game A", new VideoGamePlatformModel { Platform = "PS5", Reference = AmazonImportMergeService.FormatOrderReference("405-2222222-2222222") }),
            Game("Game B", new VideoGamePlatformModel { Platform = "PC", Reference = null })
        };

        var result = AmazonImportMergeService.FindImportedOrderIds(existingGames, g => g.Platforms.Select(p => p.Reference));

        result.Should().BeEquivalentTo(["405-2222222-2222222"]);
    }
}
