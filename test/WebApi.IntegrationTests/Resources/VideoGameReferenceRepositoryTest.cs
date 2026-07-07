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
/// Exercises <see cref="IVideoGameReferenceRepository.FindByTitleYearAsync"/>/<see cref="IVideoGameReferenceRepository.FindByTitleAsync"/>
/// against real MongoDB - same <c>ElemMatch</c>/<c>MatchedAliases</c> shape already verified for
/// <see cref="ITvShowReferenceRepository"/> (see <c>TvShowReferenceRepositoryTest</c>), applied to video games.
/// </summary>
public class VideoGameReferenceRepositoryTest(KestrelWebAppFactory<Program> factory) : IClassFixture<KestrelWebAppFactory<Program>>
{
    [Fact]
    public async Task FindByTitleYearAsync_MatchesAnAliasWhoseConfirmedYearDiffersFromTheDocumentsOwnCanonicalYear()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var alternateTitle = $"Alternate Game Title {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = "Canonical Game Title", TitleNormalized = "canonical game title", Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "1" },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2004 }]
        });

        try
        {
            var found = await repository.FindByTitleYearAsync(alternateTitle, 2004);

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
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var alternateTitle = $"Alternate Game Title {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = "Canonical Game Title", TitleNormalized = "canonical game title", Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = "1" },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2005 }]
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
    public async Task UpsertAsync_AlwaysIncludesTheCanonicalTitleAndYearInMatchedAliases_EvenIfTheCallerForgot()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Canonical Only Game Title {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = title, TitleNormalized = title.ToLowerInvariant(), Year = 2010, ExternalIds = new Dictionary<string, string> { ["rawg"] = "1" }
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
        var collection = scope.ServiceProvider.GetRequiredService<IMongoDatabase>().GetCollection<VideoGameReference>("videogame_reference");
        await collection.DeleteOneAsync(Builders<VideoGameReference>.Filter.Eq(x => x.Id, id), TestContext.Current.CancellationToken);
    }
}
