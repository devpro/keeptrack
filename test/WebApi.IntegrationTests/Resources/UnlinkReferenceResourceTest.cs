using System;
using System.Collections.Generic;
using System.Net;
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
/// Exercises POST /api/{tv-shows,movies,books,video-games,albums}/{id}/unlink-reference - the admin
/// action that clears a tenant's own <c>ReferenceId</c> and permanently deletes the shared reference
/// document behind a wrong match. The integration suite's shared Firebase test user is an admin (see
/// <c>FreeTierTest</c>'s own doc comment), so <see cref="ResourceTestBase.Authenticate"/> already
/// satisfies the endpoint's <c>AdminOnly</c> policy - the policy attribute itself is covered by a
/// reflection unit test instead (an HTTP 403 test would need a second, non-admin Firebase account this
/// suite doesn't have configured).
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
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new TvShowReferenceModel
        {
            Title = "Canonical Title",
            TitleNormalized = "canonical title",
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }]
        });

        await Authenticate();
        var created = await PostAsync("/api/tv-shows", new TvShowDto { Title = title, Year = year });
        await PostAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        try
        {
            var unlinked = await PostAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

            unlinked!.ReferenceId.Should().BeNullOrEmpty();
            (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
        }
        finally
        {
            await DeleteAsync($"/api/tv-shows/{created.Id}");
        }
    }

    [Fact]
    public async Task UnlinkReference_ClearsMovieLink_AndDeletesTheReferenceDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
        var title = $"Unlink Reference Test Movie {Guid.NewGuid()}";
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new MovieReferenceModel
        {
            Title = "Canonical Movie Title",
            TitleNormalized = "canonical movie title",
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }]
        });

        await Authenticate();
        var created = await PostAsync("/api/movies", new MovieDto { Title = title, Year = year });
        await PostAsync<MovieDto?>($"/api/movies/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        try
        {
            var unlinked = await PostAsync<MovieDto?>($"/api/movies/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

            unlinked!.ReferenceId.Should().BeNullOrEmpty();
            (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
        }
        finally
        {
            await DeleteAsync($"/api/movies/{created.Id}");
        }
    }

    [Fact]
    public async Task UnlinkReference_ClearsBookLink_AndDeletesTheReferenceDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var title = $"Unlink Reference Test Book {Guid.NewGuid()}";
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new BookReferenceModel
        {
            Title = "Canonical Book Title",
            TitleNormalized = "canonical book title",
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = "OL1W" },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year, Creator = TitleNormalizer.Normalize("Some Author") }]
        });

        await Authenticate();
        var created = await PostAsync("/api/books", new BookDto { Title = title, Author = "Some Author", Year = year });
        await PostAsync<BookDto?>($"/api/books/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        try
        {
            var unlinked = await PostAsync<BookDto?>($"/api/books/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

            unlinked!.ReferenceId.Should().BeNullOrEmpty();
            (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
        }
        finally
        {
            await DeleteAsync($"/api/books/{created.Id}");
        }
    }

    [Fact]
    public async Task UnlinkReference_ClearsVideoGameLink_AndDeletesTheReferenceDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Unlink Reference Test Game {Guid.NewGuid()}";
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = "Canonical Game Title",
            TitleNormalized = "canonical game title",
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "1" },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year }]
        });

        await Authenticate();
        var created = await PostAsync("/api/video-games", new VideoGameDto { Title = title, Year = year });
        await PostAsync<VideoGameDto?>($"/api/video-games/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        try
        {
            var unlinked = await PostAsync<VideoGameDto?>($"/api/video-games/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

            unlinked!.ReferenceId.Should().BeNullOrEmpty();
            (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
        }
        finally
        {
            await DeleteAsync($"/api/video-games/{created.Id}");
        }
    }

    [Fact]
    public async Task UnlinkReference_ClearsAlbumLink_AndDeletesTheReferenceDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var title = $"Unlink Reference Test Album {Guid.NewGuid()}";
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new AlbumReferenceModel
        {
            Title = "Canonical Album Title",
            TitleNormalized = "canonical album title",
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["discogs"] = "1" },
            MatchedAliases = [new ReferenceMatchModel { Title = TitleNormalizer.Normalize(title), Year = year, Creator = TitleNormalizer.Normalize("Some Artist") }]
        });

        await Authenticate();
        var created = await PostAsync("/api/albums", new AlbumDto { Title = title, Artist = "Some Artist", Year = year });
        await PostAsync<AlbumDto?>($"/api/albums/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

        try
        {
            var unlinked = await PostAsync<AlbumDto?>($"/api/albums/{created.Id}/unlink-reference", null, HttpStatusCode.OK);

            unlinked!.ReferenceId.Should().BeNullOrEmpty();
            (await referenceRepository.FindByIdAsync(reference.Id!)).Should().BeNull();
        }
        finally
        {
            await DeleteAsync($"/api/albums/{created.Id}");
        }
    }
}
