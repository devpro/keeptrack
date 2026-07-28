using System.Collections.Generic;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

/// <summary>
/// A copied media item carries only its identity and reference link into the recipient's collection -
/// everything personal to the sharer (rating, notes, favorite/wishlist flags, owned copies, dates) is
/// dropped, and the new owner id is stamped.
/// </summary>
[Trait("Category", "UnitTests")]
public class SharedItemCopyServiceTest
{
    private const string NewOwner = "recipient-user";

    [Fact]
    public void CopyMovie_KeepsIdentityAndReference_DropsEverythingPersonal()
    {
        var source = new MovieModel
        {
            Id = "src-id",
            OwnerId = "sharer",
            Title = "The Terminator",
            Year = 1984,
            ReferenceId = "ref-123",
            Rating = 4.5f,
            Notes = "private note",
            IsFavorite = true,
            WantToWatch = true,
            IsWishlisted = true,
            FirstSeenAt = new System.DateOnly(2020, 1, 1),
            OwnedVersions = [new OwnedVersionModel()]
        };

        var copy = SharedItemCopyService.CopyMovie(source, NewOwner);

        copy.OwnerId.Should().Be(NewOwner);
        copy.Title.Should().Be("The Terminator");
        copy.Year.Should().Be(1984);
        copy.ReferenceId.Should().Be("ref-123");

        copy.Id.Should().BeNull();
        copy.Rating.Should().BeNull();
        copy.Notes.Should().BeNull();
        copy.IsFavorite.Should().BeFalse();
        copy.WantToWatch.Should().BeFalse();
        copy.IsWishlisted.Should().BeFalse();
        copy.FirstSeenAt.Should().BeNull();
        copy.OwnedVersions.Should().BeEmpty();
    }

    [Fact]
    public void CopyBook_KeepsAuthor_DropsOwnedCopiesAndRating()
    {
        var source = new BookModel
        {
            OwnerId = "sharer",
            Title = "Killing Floor",
            Author = "Lee Child",
            Year = 1997,
            ReferenceId = "ref-book",
            Rating = 5f,
            Genre = "Thriller",
            IsFavorite = true,
            OwnedVersions = [new OwnedVersionModel()]
        };

        var copy = SharedItemCopyService.CopyBook(source, NewOwner);

        copy.OwnerId.Should().Be(NewOwner);
        copy.Title.Should().Be("Killing Floor");
        copy.Author.Should().Be("Lee Child");
        copy.Year.Should().Be(1997);
        copy.ReferenceId.Should().Be("ref-book");
        copy.Rating.Should().BeNull();
        copy.IsFavorite.Should().BeFalse();
        copy.OwnedVersions.Should().BeEmpty();
    }

    [Fact]
    public void CopyAlbum_KeepsArtist()
    {
        var source = new AlbumModel { OwnerId = "sharer", Title = "Born Pink", Artist = "BLACKPINK", Year = 2022, ReferenceId = "ref-album", Rating = 3f };

        var copy = SharedItemCopyService.CopyAlbum(source, NewOwner);

        copy.OwnerId.Should().Be(NewOwner);
        copy.Artist.Should().Be("BLACKPINK");
        copy.ReferenceId.Should().Be("ref-album");
        copy.Rating.Should().BeNull();
    }

    [Fact]
    public void CopyVideoGame_DropsPlatforms()
    {
        var source = new VideoGameModel
        {
            OwnerId = "sharer",
            Title = "God of War",
            Year = 2018,
            ReferenceId = "ref-game",
            Platforms = [new VideoGamePlatformModel { Platform = "PS5", CopyType = CopyType.Physical }]
        };

        var copy = SharedItemCopyService.CopyVideoGame(source, NewOwner);

        copy.OwnerId.Should().Be(NewOwner);
        copy.Title.Should().Be("God of War");
        copy.ReferenceId.Should().Be("ref-game");
        copy.Platforms.Should().BeEmpty();
    }
}
