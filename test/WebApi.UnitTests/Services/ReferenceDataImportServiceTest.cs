using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Moq;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

/// <summary>
/// The import decisions: which existing document an imported one lands on, what is reported instead of guessed, and how the cited people are remapped.
/// The storage side, unique indexes included, belongs to the integration tests.
/// </summary>
[Trait("Category", "UnitTests")]
public class ReferenceDataImportServiceTest
{
    private readonly Mock<ITvShowReferenceRepository> _tvShows = new();
    private readonly Mock<IMovieReferenceRepository> _movies = new();
    private readonly Mock<IPersonReferenceRepository> _people = new();
    private readonly Mock<IBookReferenceRepository> _books = new();
    private readonly Mock<IVideoGameReferenceRepository> _videoGames = new();
    private readonly Mock<IAlbumReferenceRepository> _albums = new();
    private readonly List<MovieReferenceModel> _savedMovies = [];
    private readonly List<ReferenceDataImportCollection> _started = [];

    public ReferenceDataImportServiceTest()
    {
        _tvShows.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        _tvShows.Setup(r => r.UpsertAsync(It.IsAny<TvShowReferenceModel>())).ReturnsAsync((TvShowReferenceModel m) => m);
        _people.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        _people.Setup(r => r.UpsertAsync(It.IsAny<PersonReferenceModel>())).ReturnsAsync((PersonReferenceModel m) => m);
        _books.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        _books.Setup(r => r.UpsertAsync(It.IsAny<BookReferenceModel>())).ReturnsAsync((BookReferenceModel m) => m);
        _videoGames.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        _videoGames.Setup(r => r.UpsertAsync(It.IsAny<VideoGameReferenceModel>())).ReturnsAsync((VideoGameReferenceModel m) => m);
        _albums.Setup(r => r.FindAllAsync()).ReturnsAsync([]);
        _albums.Setup(r => r.UpsertAsync(It.IsAny<AlbumReferenceModel>())).ReturnsAsync((AlbumReferenceModel m) => m);
        _movies.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>()))
            .Callback((MovieReferenceModel m) => _savedMovies.Add(m))
            .ReturnsAsync((MovieReferenceModel m) => m);
        ExistingMovies();
    }

    [Fact]
    public async Task ImportAsync_UpdatesTheDocumentHoldingTheSameProviderId_UnderTheTargetsOwnId()
    {
        ExistingMovies(Movie("target", "Heat", 1995, ("tmdb", "949")));

        var summary = await ImportAsync(Movie("exported", "Heat", 1995, ("tmdb", "949")));

        summary.Movies.Updated.Should().Be(1);
        summary.Movies.Created.Should().Be(0);
        _savedMovies.Should().ContainSingle().Which.Id.Should().Be("target", "every tenant's link points at it");
    }

    [Fact]
    public async Task ImportAsync_MergesWhatOnlyTheTargetKnows_AndTheImportWinsOnTheRest()
    {
        var existing = Movie("target", "Heat", 1995, ("tmdb", "949"), ("imdb", "tt0113277"));
        existing.Synopsis = "target synopsis";
        existing.Genres = ["Crime"];
        var imported = Movie("exported", "Heat", 1995, ("tmdb", "949"));
        imported.Synopsis = "imported synopsis";
        ExistingMovies(existing);

        await ImportAsync(imported);

        var saved = _savedMovies.Should().ContainSingle().Subject;
        saved.Synopsis.Should().Be("imported synopsis");
        saved.Genres.Should().Equal("Crime");
        saved.ExternalIds.Should().Contain("imdb", "tt0113277");
    }

    [Fact]
    public async Task ImportAsync_FallsBackToTheExportedId_ForADocumentWithNoProviderId()
    {
        ExistingMovies(Movie("same", "Heat", 1995));

        var summary = await ImportAsync(Movie("same", "Heat", 1995));

        summary.Movies.Updated.Should().Be(1);
        summary.PossibleDuplicates.Should().BeEmpty();
    }

    [Theory]
    [InlineData(1995, "Movies:Heat! (1995)")]
    [InlineData(null, "Movies:Heat!")]
    public async Task ImportAsync_ReportsACreatedDocumentNamingAWorkTheTargetKnows(int? year, string reported)
    {
        ExistingMovies(Movie("target", "Heat", year, ("tmdb", "949")));

        var summary = await ImportAsync(Movie("exported", "Heat!", year, ("other", "1")));

        summary.Movies.Created.Should().Be(1);
        summary.PossibleDuplicates.Should().Equal(reported);
    }

    [Fact]
    public async Task ImportAsync_DoesNotReportARemake_WhoseYearDiffers()
    {
        ExistingMovies(Movie("target", "Heat", 1986, ("tmdb", "1")));

        var summary = await ImportAsync(Movie("exported", "Heat", 1995, ("tmdb", "949")));

        summary.PossibleDuplicates.Should().BeEmpty();
    }

    [Fact]
    public async Task ImportAsync_ReportsTwoDocumentsOfOneArchiveNamingTheSameWork()
    {
        var summary = await ImportAsync(Movie("a", "Heat", 1995, ("tmdb", "1")), Movie("b", "Heat", 1995, ("other", "2")));

        summary.Movies.Created.Should().Be(2);
        summary.PossibleDuplicates.Should().Equal("Movies:Heat (1995)");
    }

    [Fact]
    public async Task ImportAsync_MatchesTheSecondOfTwoDocumentsOfOneArchiveSharingAProviderId()
    {
        var summary = await ImportAsync(Movie("a", "Heat", 1995, ("tmdb", "1")), Movie("b", "Heat", 1995, ("tmdb", "1")));

        summary.Movies.Created.Should().Be(1);
        summary.Movies.Updated.Should().Be(1);
        _savedMovies[1].Id.Should().Be("a");
    }

    /// <summary>The imported document names two works of the target: it lands on one, and the id of the other is left out rather than hitting its unique index.</summary>
    [Fact]
    public async Task ImportAsync_LeavesOutAProviderIdAnotherDocumentHolds_AndReportsIt()
    {
        ExistingMovies(Movie("first", "Heat", 1995, ("imdb", "tt1")), Movie("second", "Heat bis", 1996, ("tmdb", "2")));

        var summary = await ImportAsync(Movie("exported", "Heat", 1995, ("imdb", "tt1"), ("tmdb", "2")));

        var saved = _savedMovies.Should().ContainSingle().Subject;
        saved.Id.Should().Be("first");
        saved.ExternalIds.Should().NotContainKey("tmdb");
        summary.SkippedExternalIds.Should().Equal("tmdb:2");
    }

    [Fact]
    public async Task ImportAsync_PointsTheCastAtTheTargetsPeople()
    {
        _people.Setup(r => r.FindAllAsync()).ReturnsAsync([Person("target-person")]);
        var movie = Movie("exported", "Heat", 1995, ("tmdb", "949"));
        movie.Cast =
        [
            new CastMemberModel { PersonReferenceId = "exported-person", CharacterName = "Neil" },
            new CastMemberModel { PersonReferenceId = "unknown", CharacterName = "Vincent" }
        ];

        await ImportAsync(new ReferenceDataImportPayload { People = [Person("exported-person")], Movies = [movie] });

        _savedMovies.Should().ContainSingle().Which.Cast.Select(c => c.PersonReferenceId).Should().Equal("target-person", "unknown");
    }

    /// <summary>A cast kept from the target already holds the target's ids, so remapping it again would point it at another person.</summary>
    [Fact]
    public async Task ImportAsync_NeverRemapsTheCastItKeepsFromTheTarget()
    {
        _people.Setup(r => r.FindAllAsync()).ReturnsAsync([Person("target-person")]);
        var existing = Movie("target", "Heat", 1995, ("tmdb", "949"));
        existing.Cast = [new CastMemberModel { PersonReferenceId = "exported-person", CharacterName = "Neil" }];
        ExistingMovies(existing);

        await ImportAsync(new ReferenceDataImportPayload
        {
            People = [Person("exported-person")], Movies = [Movie("exported", "Heat", 1995, ("tmdb", "949"))]
        });

        _savedMovies.Should().ContainSingle().Which.Cast.Should().ContainSingle().Which.PersonReferenceId.Should().Be("exported-person");
    }

    [Fact]
    public async Task ImportAsync_RunsEveryCollection_AndReportsEachUnderItsOwnCounts()
    {
        _books.Setup(r => r.FindAllAsync()).ReturnsAsync([Book("target", ("bnf", "known"))]);
        _tvShows.Setup(r => r.FindAllAsync()).ReturnsAsync([TvShow("target", ("tmdb", "known"))]);
        _videoGames.Setup(r => r.FindAllAsync()).ReturnsAsync([VideoGame("target", ("rawg", "known"))]);
        _albums.Setup(r => r.FindAllAsync()).ReturnsAsync([Album("target", ("discogs", "known"))]);
        _people.Setup(r => r.FindAllAsync()).ReturnsAsync([Person("target-person")]);
        var book = Book("b", ("googlebooks", "1"));
        book.AuthorReferenceId = "exported-person";
        var album = Album("a", ("other", "1"));
        album.ArtistReferenceId = "exported-person";
        var show = TvShow("t", ("other", "1"));
        show.Cast = [new CastMemberModel { PersonReferenceId = "exported-person", CharacterName = "Neil" }];

        var summary = await ImportAsync(new ReferenceDataImportPayload
        {
            People = [Person("exported-person")], TvShows = [show], Books = [book], VideoGames = [VideoGame("g", ("igdb", "1"))], Albums = [album]
        });

        summary.People.Updated.Should().Be(1);
        new[] { summary.TvShows, summary.Books, summary.VideoGames, summary.Albums }.Should().AllSatisfy(c => c.Created.Should().Be(1));
        summary.Movies.Total.Should().Be(0);
        summary.PossibleDuplicates.Should().Equal("TvShows:Same (2000)", "Books:Same (2000)", "VideoGames:Same (2000)", "Albums:Same (2000)");
        book.AuthorReferenceId.Should().Be("target-person");
        album.ArtistReferenceId.Should().Be("target-person");
        show.Cast[0].PersonReferenceId.Should().Be("target-person");
        _started.Should().Equal(
            ReferenceDataImportCollection.People, ReferenceDataImportCollection.TvShows, ReferenceDataImportCollection.Movies,
            ReferenceDataImportCollection.Books, ReferenceDataImportCollection.VideoGames, ReferenceDataImportCollection.Albums);
    }

    [Fact]
    public async Task ImportAsync_DoesNotReadACollectionTheArchiveDoesNotHold()
    {
        await ImportAsync(new ReferenceDataImportPayload());

        _movies.Verify(r => r.FindAllAsync(), Times.Never);
        _people.Verify(r => r.FindAllAsync(), Times.Never);
    }

    [Fact]
    public async Task ImportAsync_StopsBetweenDocuments_WhenCancelled()
    {
        using var source = new CancellationTokenSource();
        _movies.Setup(r => r.UpsertAsync(It.IsAny<MovieReferenceModel>()))
            .Callback((MovieReferenceModel m) =>
            {
                _savedMovies.Add(m);
                source.Cancel();
            })
            .ReturnsAsync((MovieReferenceModel m) => m);

        var import = () => ImportAsync(
            new ReferenceDataImportPayload { Movies = [Movie("a", "Heat", 1995), Movie("b", "Ronin", 1998)] }, source.Token);

        await import.Should().ThrowAsync<OperationCanceledException>();
        _savedMovies.Should().ContainSingle();
    }

    private void ExistingMovies(params MovieReferenceModel[] movies) => _movies.Setup(r => r.FindAllAsync()).ReturnsAsync([.. movies]);

    private Task<ReferenceDataImportSummary> ImportAsync(params MovieReferenceModel[] movies) =>
        ImportAsync(new ReferenceDataImportPayload { Movies = [.. movies] });

    private Task<ReferenceDataImportSummary> ImportAsync(ReferenceDataImportPayload payload, CancellationToken? cancellationToken = null) =>
        ReferenceDataImportService.ImportAsync(
            payload,
            new ReferenceRepositorySet(_tvShows.Object, _movies.Object, _people.Object, _books.Object, _videoGames.Object, _albums.Object),
            collection =>
            {
                _started.Add(collection);
                return Task.CompletedTask;
            },
            cancellationToken ?? TestContext.Current.CancellationToken);

    private static Dictionary<string, string> Ids((string Provider, string Id)[] ids) => ids.ToDictionary(i => i.Provider, i => i.Id);

    private static MovieReferenceModel Movie(string id, string title, int? year, params (string Provider, string Id)[] ids) =>
        new() { Id = id, Title = title, TitleNormalized = title, Year = year, ExternalIds = Ids(ids) };

    private static PersonReferenceModel Person(string id) => new() { Id = id, Name = "Robert De Niro", ExternalIds = Ids([("tmdb", "380")]) };

    private static TvShowReferenceModel TvShow(string id, params (string Provider, string Id)[] ids) =>
        new() { Id = id, Title = "Same", TitleNormalized = "same", Year = 2000, ExternalIds = Ids(ids) };

    private static BookReferenceModel Book(string id, params (string Provider, string Id)[] ids) =>
        new() { Id = id, Title = "Same", TitleNormalized = "same", Year = 2000, ExternalIds = Ids(ids) };

    private static VideoGameReferenceModel VideoGame(string id, params (string Provider, string Id)[] ids) =>
        new() { Id = id, Title = "Same", TitleNormalized = "same", Year = 2000, ExternalIds = Ids(ids) };

    private static AlbumReferenceModel Album(string id, params (string Provider, string Id)[] ids) =>
        new() { Id = id, Title = "Same", TitleNormalized = "same", Year = 2000, ExternalIds = Ids(ids) };
}
