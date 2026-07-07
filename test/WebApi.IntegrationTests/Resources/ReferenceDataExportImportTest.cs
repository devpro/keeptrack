using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises the reference repositories' <c>FindAllAsync</c> (backs the admin zip export) directly against
/// real MongoDB, and confirms re-upserting an already-exported document (the zip import path) is a true
/// no-op the second time - the whole point of "idempotent" for POST /api/reference-data/import.
/// </summary>
public class ReferenceDataExportImportTest(KestrelWebAppFactory<Program> factory) : IClassFixture<KestrelWebAppFactory<Program>>
{
    [Fact]
    public async Task TvShowReferenceRepository_FindAllAsync_IncludesEveryDocument()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Export Test Show {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new TvShowReferenceModel
        {
            Title = title, TitleNormalized = title.ToLowerInvariant(), Year = 2020, ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" }
        });

        try
        {
            var all = await repository.FindAllAsync();

            all.Should().Contain(m => m.Id == created.Id && m.Title == title);
        }
        finally
        {
            await DeleteAsync<TvShowReference>(scope, "tvshow_reference", created.Id!);
        }
    }

    [Fact]
    public async Task TvShowReferenceRepository_ReimportingTheSameExportedDocument_IsANoOp()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Reimport Test Show {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new TvShowReferenceModel
        {
            Title = title, TitleNormalized = title.ToLowerInvariant(), Year = 2020, ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" }
        });

        try
        {
            // simulates re-running an import of a previously exported document: same id, same content
            await repository.UpsertAsync(new TvShowReferenceModel
            {
                Id = created.Id, Title = title, TitleNormalized = title.ToLowerInvariant(), Year = 2020,
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" }
            });

            var all = await repository.FindAllAsync();

            all.Count(m => m.Id == created.Id).Should().Be(1);
        }
        finally
        {
            await DeleteAsync<TvShowReference>(scope, "tvshow_reference", created.Id!);
        }
    }

    [Fact]
    public async Task MovieReferenceRepository_FindAllAsync_IncludesEveryDocument()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
        var title = $"Export Test Movie {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new MovieReferenceModel
        {
            Title = title, TitleNormalized = title.ToLowerInvariant(), Year = 2020, ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" }
        });

        try
        {
            var all = await repository.FindAllAsync();

            all.Should().Contain(m => m.Id == created.Id && m.Title == title);
        }
        finally
        {
            await DeleteAsync<MovieReference>(scope, "movie_reference", created.Id!);
        }
    }

    [Fact]
    public async Task PersonReferenceRepository_FindAllAsync_IncludesEveryDocument()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IPersonReferenceRepository>();
        var tmdbId = Guid.NewGuid().ToString();

        var created = await repository.UpsertAsync(new PersonReferenceModel
        {
            Name = "Export Test Actor", ExternalIds = new Dictionary<string, string> { ["tmdb"] = tmdbId }
        });

        try
        {
            var all = await repository.FindAllAsync();

            all.Should().Contain(p => p.Id == created.Id && p.Name == "Export Test Actor");
        }
        finally
        {
            await DeleteAsync<PersonReference>(scope, "person_reference", created.Id!);
        }
    }

    private static async Task DeleteAsync<TEntity>(IServiceScope scope, string collectionName, string id) where TEntity : class
    {
        var collection = scope.ServiceProvider.GetRequiredService<IMongoDatabase>().GetCollection<TEntity>(collectionName);
        await collection.DeleteOneAsync(Builders<TEntity>.Filter.Eq("_id", id), TestContext.Current.CancellationToken);
    }
}
