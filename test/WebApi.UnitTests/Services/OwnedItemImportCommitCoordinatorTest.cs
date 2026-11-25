using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Moq;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

/// <summary>
/// The split of reviewed rows over the six types: each row reaches its own repository with its fields, and each type reports its own counts.
/// </summary>
[Trait("Category", "UnitTests")]
public class OwnedItemImportCommitCoordinatorTest
{
    private readonly Mock<IBookRepository> _books = new();
    private readonly Mock<IMovieRepository> _movies = new();
    private readonly Mock<ITvShowRepository> _tvShows = new();
    private readonly Mock<IVideoGameRepository> _videoGames = new();
    private readonly Mock<IGearRepository> _gear = new();
    private readonly Mock<ICollectibleRepository> _collectibles = new();

    [Fact]
    public async Task CommitAsync_CreatesEachRowInItsOwnCollection()
    {
        var books = Track<IBookRepository, BookModel>(_books);
        var movies = Track<IMovieRepository, MovieModel>(_movies);
        var tvShows = Track<ITvShowRepository, TvShowModel>(_tvShows);
        var videoGames = Track<IVideoGameRepository, VideoGameModel>(_videoGames);
        var gear = Track<IGearRepository, GearModel>(_gear);
        var collectibles = Track<ICollectibleRepository, CollectibleModel>(_collectibles);

        var counts = await CommitAsync(
            Row(ImportMediaType.Book, "book"), Row(ImportMediaType.Movie, "movie"), Row(ImportMediaType.TvShow, "show"),
            Row(ImportMediaType.VideoGame, "game"), Row(ImportMediaType.Gear, "gear"), Row(ImportMediaType.Collectible, "collectible"));

        var book = books.Should().ContainSingle().Subject;
        (book.OwnerId, book.Title, book.Author, book.Isbn, book.Year, book.Notes).Should().Be(("owner", "book", "author", "isbn", 2001, "notes"));
        book.OwnedVersions.Should().ContainSingle().Which.Reference.Should().Be("ref-book");
        var movie = movies.Should().ContainSingle().Subject;
        (movie.OwnerId, movie.Title, movie.Year, movie.Notes, movie.OwnedVersions.Single().Reference).Should().Be(("owner", "movie", 2001, "notes", "ref-movie"));
        var show = tvShows.Should().ContainSingle().Subject;
        (show.OwnerId, show.Title, show.Year, show.Notes, show.OwnedVersions.Single().Reference).Should().Be(("owner", "show", 2001, "notes", "ref-show"));
        var game = videoGames.Should().ContainSingle().Subject;
        (game.OwnerId, game.Title, game.Year, game.Notes).Should().Be(("owner", "game", 2001, "notes"));
        (game.Platforms.Single().Platform, game.Platforms.Single().Reference, game.Platforms.Single().Vendor).Should().Be(("Switch", "ref-game", "shop"));
        var gearItem = gear.Should().ContainSingle().Subject;
        (gearItem.OwnerId, gearItem.Title, gearItem.Year, gearItem.Notes, gearItem.OwnedVersions.Single().Reference).Should().Be(("owner", "gear", 2001, "notes", "ref-gear"));
        var collectible = collectibles.Should().ContainSingle().Subject;
        (collectible.OwnerId, collectible.Title, collectible.Year, collectible.Notes, collectible.OwnedVersions.Single().Reference)
            .Should().Be(("owner", "collectible", 2001, "notes", "ref-collectible"));

        new[] { counts.Books, counts.Movies, counts.TvShows, counts.VideoGames, counts.Gear, counts.Collectibles }
            .Should().AllSatisfy(c => (c.Created, c.MergedInto, c.Skipped).Should().Be((1, 0, 0)));
        counts.RowsImported.Should().Be(6);
        counts.SkippedTitles.Should().BeEmpty();
    }

    [Fact]
    public async Task CommitAsync_MergesIntoAnExistingTitle_AndSkipsAKnownReference()
    {
        var existing = new MovieModel
        {
            Id = "m1", OwnerId = "owner", Title = "movie", OwnedVersions = [new OwnedVersionModel { CopyType = CopyType.Physical, Reference = "ref-known" }]
        };
        var created = Track(_movies, existing);

        var counts = await CommitAsync(Row(ImportMediaType.Movie, "movie"), Row(ImportMediaType.Movie, "movie", "ref-known"));

        created.Should().BeEmpty();
        existing.OwnedVersions.Select(v => v.Reference).Should().Equal("ref-known", "ref-movie");
        _movies.Verify(r => r.UpdateAsync("m1", existing, "owner", It.IsAny<CancellationToken>()), Times.Once);
        (counts.Movies.Created, counts.Movies.MergedInto, counts.Movies.Skipped).Should().Be((0, 1, 1));
        counts.RowsImported.Should().Be(1);
        counts.SkippedTitles.Should().Equal("movie");
    }

    [Fact]
    public async Task CommitAsync_AddsAPlatformToAnExistingGame()
    {
        var existing = new VideoGameModel { Id = "g1", OwnerId = "owner", Title = "game" };
        Track(_videoGames, existing);

        var counts = await CommitAsync(Row(ImportMediaType.VideoGame, "game"));

        existing.Platforms.Should().ContainSingle().Which.Platform.Should().Be("Switch");
        counts.VideoGames.MergedInto.Should().Be(1);
    }

    [Fact]
    public async Task CommitAsync_DoesNotReadATypeNoRowHas()
    {
        Track<IMovieRepository, MovieModel>(_movies);

        await CommitAsync(Row(ImportMediaType.Movie, "movie"));

        _books.Invocations.Should().BeEmpty();
        _gear.Invocations.Should().BeEmpty();
    }

    private Task<OwnedItemImportCommitCounts> CommitAsync(params OwnedItemImportInput[] inputs) =>
        OwnedItemImportCommitCoordinator.CommitAsync(
            "owner", inputs,
            new OwnedItemRepositorySet(_books.Object, _movies.Object, _tvShows.Object, _videoGames.Object, _gear.Object, _collectibles.Object));

    private static List<TModel> Track<TRepository, TModel>(Mock<TRepository> repository, params TModel[] existing)
        where TRepository : class, IDataRepository<TModel>
        where TModel : class, IHasIdAndOwnerId
    {
        var created = new List<TModel>();
        repository.As<IDataRepository<TModel>>()
            .Setup(r => r.FindAllAsync("owner", 1, int.MaxValue, null, It.IsAny<TModel>(), null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PagedResult<TModel>([.. existing], existing.Length, 1, int.MaxValue));
        repository.As<IDataRepository<TModel>>().Setup(r => r.CreateAsync(It.IsAny<TModel>(), It.IsAny<CancellationToken>()))
            .Callback((TModel m, CancellationToken _) => created.Add(m))
            .ReturnsAsync((TModel m, CancellationToken _) => m);
        return created;
    }

    private static OwnedItemImportInput Row(ImportMediaType type, string title, string? reference = null) => new()
    {
        MediaType = type,
        Title = title,
        Author = "author",
        Isbn = "isbn",
        Year = 2001,
        Platform = "Switch",
        ProvenanceNotes = "notes",
        OwnedVersion = new OwnedVersionModel { CopyType = CopyType.Physical, Reference = reference ?? $"ref-{title}", Vendor = "shop" }
    };
}
