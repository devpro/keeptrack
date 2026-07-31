using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises <see cref="IVideoGameReferenceRepository.FindByTitleYearAsync"/>/<see cref="IVideoGameReferenceRepository.FindByTitleAsync"/>
/// against real MongoDB - same <c>ElemMatch</c>/<c>MatchedAliases</c> shape already verified for
/// <see cref="ITvShowReferenceRepository"/> (see <c>TvShowReferenceRepositoryTest</c>), applied to video games.
/// </summary>
public class VideoGameReferenceRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindByTitleYearAsync_MatchesAnAliasWhoseConfirmedYearDiffersFromTheDocumentsOwnCanonicalYear()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var alternateTitle = $"Alternate Game Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new VideoGameReferenceModel
        {
            Title = "Canonical Game Title",
            TitleNormalized = "canonical game title",
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2004 }]
        });

        var found = await repository.FindByTitleYearAsync(alternateTitle, 2004);

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    [Fact]
    public async Task FindByTitleAsync_MatchesAnAlternateTitle_IgnoringYear()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var alternateTitle = $"Alternate Game Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new VideoGameReferenceModel
        {
            Title = "Canonical Game Title",
            TitleNormalized = "canonical game title",
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2005 }]
        });

        var found = await repository.FindByTitleAsync(alternateTitle);

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    [Fact]
    public async Task UpsertAsync_AlwaysIncludesTheCanonicalTitleAndYearInMatchedAliases_EvenIfTheCallerForgot()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Canonical Only Game Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new VideoGameReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2010,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = TestExternalId.New() }
        });

        var found = await repository.FindByTitleAsync(title);

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    private async Task<VideoGameReferenceModel> CreateReferenceAsync(IVideoGameReferenceRepository repository, VideoGameReferenceModel model)
    {
        var created = await repository.UpsertAsync(model);
        TrackDocument("videogame_reference", created.Id);
        return created;
    }
}
