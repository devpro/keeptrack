using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises POST /api/{tv-shows,movies,books,video-games,albums}/{id}/unlink-reference - the admin
/// action that clears a tenant's own <c>ReferenceId</c> and permanently deletes the shared reference
/// document behind a wrong match. The integration suite's shared Firebase test user is an admin (see
/// <c>FreeTierTest</c>'s own doc comment), so <see cref="ResourceTestBase.Authenticate"/> already
/// satisfies the endpoint's <c>AdminOnly</c> policy - the policy attribute itself is covered by a
/// reflection unit test instead (an HTTP 403 test would need a second, non-admin Firebase account this
/// suite doesn't have configured).
/// <para>
/// Each reference document is registered for deletion even though the endpoint under test is supposed to
/// delete it: the registration is what covers the run where the endpoint *doesn't*, which is the
/// regression these tests exist to catch. Deleting an already-deleted document is a no-op.
/// </para>
/// </summary>
public class UnlinkReferenceResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task UnlinkReference_ClearsTvShowLink_AndDeletesTheReferenceDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Unlink Reference Test Show {Guid.NewGuid()}";
        // unique per test, like the searched title: creating the item links it in the background, which rewrites its title to the canonical one, so the refresh below looks the *canonical* title up.
        // A canonical title two tests share would let that lookup answer with the other test's document - and this test would then delete that one and report its own as undeleted.
        var canonicalTitle = $"Canonical Unlink Show {Guid.NewGuid()}";
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new TvShowReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Year = year },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }
            ]
        });
        TrackDocument("tvshow_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/tv-shows", new TvShowDto { Title = title, Year = year });
        await PostAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        var unlinked = await PostAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

        unlinked!.ReferenceId.Should().BeNullOrEmpty();
        (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
    }

    [Fact]
    public async Task UnlinkReference_ClearsMovieLink_AndDeletesTheReferenceDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
        var title = $"Unlink Reference Test Movie {Guid.NewGuid()}";
        var canonicalTitle = $"Canonical Unlink Movie {Guid.NewGuid()}"; // see the TV show case
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new MovieReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Year = year },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }
            ]
        });
        TrackDocument("movie_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/movies", new MovieDto { Title = title, Year = year });
        await PostAsync<MovieDto?>($"/api/movies/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        var unlinked = await PostAsync<MovieDto?>($"/api/movies/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

        unlinked!.ReferenceId.Should().BeNullOrEmpty();
        (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
    }

    [Fact]
    public async Task UnlinkReference_ClearsBookLink_AndDeletesTheReferenceDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var title = $"Unlink Reference Test Book {Guid.NewGuid()}";
        var canonicalTitle = $"Canonical Unlink Book {Guid.NewGuid()}"; // see the TV show case
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new BookReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = TestExternalId.New() },
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Year = year, Creator = TitleNormalizer.Normalize("Some Author") },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year, Creator = TitleNormalizer.Normalize("Some Author") }
            ]
        });
        TrackDocument("book_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/books", new BookDto { Title = title, Author = "Some Author", Year = year });
        await PostAsync<BookDto?>($"/api/books/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        var unlinked = await PostAsync<BookDto?>($"/api/books/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

        unlinked!.ReferenceId.Should().BeNullOrEmpty();
        (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
    }

    [Fact]
    public async Task UnlinkReference_ClearsVideoGameLink_AndDeletesTheReferenceDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Unlink Reference Test Game {Guid.NewGuid()}";
        var canonicalTitle = $"Canonical Unlink Game {Guid.NewGuid()}"; // see the TV show case
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = TestExternalId.New() },
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Year = year },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }
            ]
        });
        TrackDocument("videogame_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/video-games", new VideoGameDto { Title = title, Year = year });
        await PostAsync<VideoGameDto?>($"/api/video-games/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        var unlinked = await PostAsync<VideoGameDto?>($"/api/video-games/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

        unlinked!.ReferenceId.Should().BeNullOrEmpty();
        (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
    }

    [Fact]
    public async Task UnlinkReference_ClearsAlbumLink_AndDeletesTheReferenceDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var title = $"Unlink Reference Test Album {Guid.NewGuid()}";
        var canonicalTitle = $"Canonical Unlink Album {Guid.NewGuid()}"; // see the TV show case
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new AlbumReferenceModel
        {
            Title = canonicalTitle,
            TitleNormalized = TitleNormalizer.Normalize(canonicalTitle),
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() },
            MatchedAliases =
            [
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(canonicalTitle), Creator = TitleNormalizer.Normalize("Some Artist") },
                new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Creator = TitleNormalizer.Normalize("Some Artist") }
            ]
        });
        TrackDocument("album_reference", reference.Id);

        await Authenticate();
        var created = await CreateAsync("/api/albums", new AlbumDto { Title = title, Artist = "Some Artist", Year = year });
        await PostAsync<AlbumDto?>($"/api/albums/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        var unlinked = await PostAsync<AlbumDto?>($"/api/albums/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

        unlinked!.ReferenceId.Should().BeNullOrEmpty();
        (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
    }
}
