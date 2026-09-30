using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Creating an item or checking it for a reference match links that one item and never another record.
/// Another owner's copy of the same work keeps its own state until its owner checks it, or an admin links it.
/// A seeded local reference answers every lookup, so no provider is called.
/// </summary>
public abstract class ReferenceLinkScopeTestBase<TDto, TModel, TRepository>(KestrelWebAppFactory<Program> factory) : ResourceTestBase(factory)
    where TDto : IHasId
    where TModel : class, IHasIdAndOwnerId, IReferenceLinkedModel
    where TRepository : IDataRepository<TModel>
{
    private const string OtherOwnerId = "reference-link-scope-other";

    private const int Year = 2001;

    private const string Creator = "Reference Link Scope Creator";

    protected abstract string Route { get; }

    protected abstract string ReferenceCollection { get; }

    protected abstract TDto NewDto(string title, int year, string creator);

    protected abstract TModel NewModel(string ownerId, string title, int year, string creator);

    /// <summary>Stores a reference whose alias answers this domain's local lookup for the title, year and creator, and returns its id.</summary>
    protected abstract Task<string> SeedReferenceAsync(IServiceProvider services, string title, int year, string creator);

    [Fact]
    public async Task CreatingAnItem_LinksIt_AndLeavesAnotherOwnersCopyAlone()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<TRepository>();
        var title = $"Reference Link Scope {Guid.NewGuid():N}";
        var referenceId = await SeedTrackedReferenceAsync(scope.ServiceProvider, title);
        var otherCopy = await SeedCopyAsync(repository, OtherOwnerId, title);

        await Authenticate();
        var created = await CreateAsync(Route, NewDto(title, Year, Creator));

        (await WaitForLinkAsync(repository, AuthenticatedUserId, created.Id!)).Should().Be(referenceId);
        (await ReadLinkAsync(repository, OtherOwnerId, otherCopy)).Should().BeNullOrEmpty("creating an item never changes an existing record");
    }

    [Fact]
    public async Task CheckingForAReferenceMatch_LinksOnlyThatItem()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<TRepository>();
        var title = $"Reference Link Scope {Guid.NewGuid():N}";
        var referenceId = await SeedTrackedReferenceAsync(scope.ServiceProvider, title);
        await Authenticate();
        var ownCopy = await SeedCopyAsync(repository, AuthenticatedUserId, title);
        var otherCopy = await SeedCopyAsync(repository, OtherOwnerId, title);

        await PostAsync<object?>($"{Route}/{ownCopy}/refresh-reference", null, System.Net.HttpStatusCode.OK);

        (await ReadLinkAsync(repository, AuthenticatedUserId, ownCopy)).Should().Be(referenceId);
        (await ReadLinkAsync(repository, OtherOwnerId, otherCopy)).Should().BeNullOrEmpty("the check only answers for the item it was asked on");
    }

    private async Task<string> SeedTrackedReferenceAsync(IServiceProvider services, string title)
    {
        var referenceId = await SeedReferenceAsync(services, title, Year, Creator);
        TrackDocument(ReferenceCollection, referenceId);
        return referenceId;
    }

    // seeded through the repository rather than posted, so no creation-time resolution runs for it
    private async Task<string> SeedCopyAsync(TRepository repository, string ownerId, string title)
    {
        var created = await repository.CreateAsync(NewModel(ownerId, title, Year, Creator));
        TrackCleanup(() => repository.DeleteAsync(created.Id!, ownerId));
        return created.Id!;
    }

    private static async Task<string?> ReadLinkAsync(TRepository repository, string ownerId, string id) =>
        (await repository.FindOneAsync(id, ownerId))?.ReferenceId;

    // creation resolves in the background, so the link lands some time after the POST answers
    private static async Task<string?> WaitForLinkAsync(TRepository repository, string ownerId, string id)
    {
        for (var attempt = 0; attempt < 50; attempt++)
        {
            var link = await ReadLinkAsync(repository, ownerId, id);
            if (!string.IsNullOrEmpty(link)) return link;
            await Task.Delay(200);
        }

        return null;
    }
}

public class TvShowReferenceLinkScopeTest(KestrelWebAppFactory<Program> factory)
    : ReferenceLinkScopeTestBase<TvShowDto, TvShowModel, ITvShowRepository>(factory)
{
    protected override string Route => "/api/tv-shows";

    protected override string ReferenceCollection => "tvshow_reference";

    protected override TvShowDto NewDto(string title, int year, string creator) => new() { Title = title, Year = year };

    protected override TvShowModel NewModel(string ownerId, string title, int year, string creator) => new() { OwnerId = ownerId, Title = title, Year = year };

    protected override async Task<string> SeedReferenceAsync(IServiceProvider services, string title, int year, string creator) =>
        (await services.GetRequiredService<ITvShowReferenceRepository>().UpsertAsync(new TvShowReferenceModel
        {
            Title = title,
            TitleNormalized = TitleNormalizer.Normalize(title),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }]
        })).Id!;
}

public class MovieReferenceLinkScopeTest(KestrelWebAppFactory<Program> factory)
    : ReferenceLinkScopeTestBase<MovieDto, MovieModel, IMovieRepository>(factory)
{
    protected override string Route => "/api/movies";

    protected override string ReferenceCollection => "movie_reference";

    protected override MovieDto NewDto(string title, int year, string creator) => new() { Title = title, Year = year };

    protected override MovieModel NewModel(string ownerId, string title, int year, string creator) => new() { OwnerId = ownerId, Title = title, Year = year };

    protected override async Task<string> SeedReferenceAsync(IServiceProvider services, string title, int year, string creator) =>
        (await services.GetRequiredService<IMovieReferenceRepository>().UpsertAsync(new MovieReferenceModel
        {
            Title = title,
            TitleNormalized = TitleNormalizer.Normalize(title),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }]
        })).Id!;
}

public class BookReferenceLinkScopeTest(KestrelWebAppFactory<Program> factory)
    : ReferenceLinkScopeTestBase<BookDto, BookModel, IBookRepository>(factory)
{
    protected override string Route => "/api/books";

    protected override string ReferenceCollection => "book_reference";

    protected override BookDto NewDto(string title, int year, string creator) => new() { Title = title, Year = year, Author = creator };

    protected override BookModel NewModel(string ownerId, string title, int year, string creator) => new() { OwnerId = ownerId, Title = title, Year = year, Author = creator };

    protected override async Task<string> SeedReferenceAsync(IServiceProvider services, string title, int year, string creator) =>
        (await services.GetRequiredService<IBookReferenceRepository>().UpsertAsync(new BookReferenceModel
        {
            Title = title,
            TitleNormalized = TitleNormalizer.Normalize(title),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["googlebooks"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year, Creator = TitleNormalizer.Normalize(creator) }]
        })).Id!;
}

public class VideoGameReferenceLinkScopeTest(KestrelWebAppFactory<Program> factory)
    : ReferenceLinkScopeTestBase<VideoGameDto, VideoGameModel, IVideoGameRepository>(factory)
{
    protected override string Route => "/api/video-games";

    protected override string ReferenceCollection => "videogame_reference";

    protected override VideoGameDto NewDto(string title, int year, string creator) => new() { Title = title, Year = year };

    protected override VideoGameModel NewModel(string ownerId, string title, int year, string creator) => new() { OwnerId = ownerId, Title = title, Year = year };

    protected override async Task<string> SeedReferenceAsync(IServiceProvider services, string title, int year, string creator) =>
        (await services.GetRequiredService<IVideoGameReferenceRepository>().UpsertAsync(new VideoGameReferenceModel
        {
            Title = title,
            TitleNormalized = TitleNormalizer.Normalize(title),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["igdb"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }]
        })).Id!;
}

public class AlbumReferenceLinkScopeTest(KestrelWebAppFactory<Program> factory)
    : ReferenceLinkScopeTestBase<AlbumDto, AlbumModel, IAlbumRepository>(factory)
{
    protected override string Route => "/api/albums";

    protected override string ReferenceCollection => "album_reference";

    protected override AlbumDto NewDto(string title, int year, string creator) => new() { Title = title, Year = year, Artist = creator };

    protected override AlbumModel NewModel(string ownerId, string title, int year, string creator) => new() { OwnerId = ownerId, Title = title, Year = year, Artist = creator };

    protected override async Task<string> SeedReferenceAsync(IServiceProvider services, string title, int year, string creator) =>
        (await services.GetRequiredService<IAlbumReferenceRepository>().UpsertAsync(new AlbumReferenceModel
        {
            Title = title,
            TitleNormalized = TitleNormalizer.Normalize(title),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Creator = TitleNormalizer.Normalize(creator) }]
        })).Id!;
}
