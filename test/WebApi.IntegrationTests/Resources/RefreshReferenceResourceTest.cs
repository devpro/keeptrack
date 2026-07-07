using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises POST /api/tv-shows/{id}/refresh-reference and /api/movies/{id}/refresh-reference - the
/// user-triggered, exact-match-only re-check against the local reference collection. Deliberately not
/// admin-gated (unlike the TMDB search/link endpoints), so the standard test user can call it directly.
/// </summary>
public class RefreshReferenceResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task RefreshReference_LinksTvShow_WhenAnExistingReferenceMatchesByTitleAndYear()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Refresh Reference Test Show {Guid.NewGuid()}";
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new TvShowReferenceModel
        {
            Title = "Canonical Title", TitleNormalized = "canonical title", Year = year, ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" }
        });

        await Authenticate();
        var created = await PostAsync("/api/tv-shows", new TvShowDto { Title = title, Year = year });

        try
        {
            var refreshed = await PostAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

            refreshed!.ReferenceId.Should().Be(reference.Id);
            refreshed.Title.Should().Be("Canonical Title");
        }
        finally
        {
            await DeleteAsync($"/api/tv-shows/{created.Id}");
            await DeleteReferenceAsync<TvShowReference>(scope, "tvshow_reference", reference.Id!);
        }
    }

    [Fact]
    public async Task RefreshReference_LeavesTvShowUnresolved_WhenNoMatchingReferenceExists()
    {
        await Authenticate();
        var title = $"Refresh Reference No Match {Guid.NewGuid()}";
        var created = await PostAsync("/api/tv-shows", new TvShowDto { Title = title, Year = 2019 });

        try
        {
            var refreshed = await PostAsync<TvShowDto?>($"/api/tv-shows/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

            refreshed!.ReferenceId.Should().BeNullOrEmpty();
        }
        finally
        {
            await DeleteAsync($"/api/tv-shows/{created.Id}");
        }
    }

    [Fact]
    public async Task RefreshReference_LinksMovie_WhenAnExistingReferenceMatchesByTitleAndYear()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
        var title = $"Refresh Reference Test Movie {Guid.NewGuid()}";
        const int year = 2019;

        var reference = await referenceRepository.UpsertAsync(new MovieReferenceModel
        {
            Title = "Canonical Movie Title", TitleNormalized = "canonical movie title", Year = year, ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" }
        });

        await Authenticate();
        var created = await PostAsync("/api/movies", new MovieDto { Title = title, Year = year });

        try
        {
            var refreshed = await PostAsync<MovieDto?>($"/api/movies/{created.Id}/refresh-reference", null, HttpStatusCode.OK);

            refreshed!.ReferenceId.Should().Be(reference.Id);
            refreshed.Title.Should().Be("Canonical Movie Title");
        }
        finally
        {
            await DeleteAsync($"/api/movies/{created.Id}");
            await DeleteReferenceAsync<MovieReference>(scope, "movie_reference", reference.Id!);
        }
    }

    private static async Task DeleteReferenceAsync<TEntity>(IServiceScope scope, string collectionName, string id) where TEntity : class
    {
        var collection = scope.ServiceProvider.GetRequiredService<IMongoDatabase>().GetCollection<TEntity>(collectionName);
        await collection.DeleteOneAsync(Builders<TEntity>.Filter.Eq("_id", id), TestContext.Current.CancellationToken);
    }
}
