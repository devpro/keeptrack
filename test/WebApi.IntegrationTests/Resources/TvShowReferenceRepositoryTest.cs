using System;
using System.Collections.Generic;
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
/// Exercises <see cref="ITvShowReferenceRepository.FindByTitleYearAsync"/>/<see cref="ITvShowReferenceRepository.FindByTitleAsync"/>
/// against real MongoDB - both now match against every entry in <c>MatchedTitles</c> (an array-contains
/// filter via <c>Builders.Filter.AnyEq</c>, backing a multikey index), not just the document's own
/// canonical <c>TitleNormalized</c>. This is exactly the kind of hand-written Mongo filter that has hidden
/// real bugs before (see docs/code-quality-findings.md), so it's verified against a real database, not mocks.
/// </summary>
public class TvShowReferenceRepositoryTest(KestrelWebAppFactory<Program> factory) : IClassFixture<KestrelWebAppFactory<Program>>
{
    [Fact]
    public async Task FindByTitleYearAsync_MatchesAnAlternateTitle_NotJustTheCanonicalOne()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var alternateTitle = $"Alternate Title {Guid.NewGuid()}";
        const int year = 2005;

        var created = await repository.UpsertAsync(new TvShowReferenceModel
        {
            Title = "Canonical Title",
            TitleNormalized = "canonical title",
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" },
            MatchedTitles = [alternateTitle.ToLowerInvariant()]
        });

        try
        {
            // case-insensitive: normalization lower-cases before comparing
            var found = await repository.FindByTitleYearAsync(alternateTitle.ToUpperInvariant(), year);

            found.Should().NotBeNull();
            found!.Id.Should().Be(created.Id);
        }
        finally
        {
            await DeleteAsync(scope, created.Id!);
        }
    }

    [Fact]
    public async Task FindByTitleAsync_MatchesAnAlternateTitle_IgnoringYear()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var alternateTitle = $"Alternate Title {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new TvShowReferenceModel
        {
            Title = "Canonical Title",
            TitleNormalized = "canonical title",
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" },
            MatchedTitles = [alternateTitle.ToLowerInvariant()]
        });

        try
        {
            var found = await repository.FindByTitleAsync(alternateTitle);

            found.Should().NotBeNull();
            found!.Id.Should().Be(created.Id);
        }
        finally
        {
            await DeleteAsync(scope, created.Id!);
        }
    }

    [Fact]
    public async Task UpsertAsync_AlwaysIncludesTheCanonicalTitleInMatchedTitles_EvenIfTheCallerForgot()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Canonical Only Title {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new TvShowReferenceModel
        {
            Title = title, TitleNormalized = title.ToLowerInvariant(), Year = 2010, ExternalIds = new Dictionary<string, string> { ["tmdb"] = "1" }
        });

        try
        {
            var found = await repository.FindByTitleAsync(title);

            found.Should().NotBeNull();
            found!.Id.Should().Be(created.Id);
        }
        finally
        {
            await DeleteAsync(scope, created.Id!);
        }
    }

    private static async Task DeleteAsync(IServiceScope scope, string id)
    {
        var collection = scope.ServiceProvider.GetRequiredService<IMongoDatabase>().GetCollection<TvShowReference>("tvshow_reference");
        await collection.DeleteOneAsync(Builders<TvShowReference>.Filter.Eq(x => x.Id, id), TestContext.Current.CancellationToken);
    }
}
