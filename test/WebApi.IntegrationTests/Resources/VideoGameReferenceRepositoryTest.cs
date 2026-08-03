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

    [Fact]
    public async Task FindByExternalIdAsync_FindsAReferenceByEitherProvidersId()
    {
        // video games are the one domain where a single reference legitimately carries two providers' ids: it
        // was linked through RAWG and later adopted an IGDB one. Both must resolve to the same document, or a
        // re-resolve through the other provider would create a duplicate instead of updating this one.
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var rawgId = TestExternalId.New();
        var igdbId = TestExternalId.New();
        var title = $"Two Provider Game {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new VideoGameReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2004,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = rawgId, ["igdb"] = igdbId }
        });

        (await repository.FindByExternalIdAsync("rawg", rawgId))!.Id.Should().Be(created.Id);
        (await repository.FindByExternalIdAsync("igdb", igdbId))!.Id.Should().Be(created.Id);
        // and an id belonging to the other provider's number space must not match: they are both plain
        // integers, so nothing but the provider key tells them apart
        (await repository.FindByExternalIdAsync("igdb", rawgId)).Should().BeNull();
    }

    // There is deliberately no "a duplicate external id is rejected" test here, for igdb or for rawg - and
    // none on the other four reference collections either. The uniqueness guarantee is real (a unique partial
    // index per provider key, declared in scripts/mongodb-create-index.js), but nothing in this suite creates
    // indexes: they are applied by running that script against the database out of band. A test asserting the
    // constraint therefore passes or fails on whether someone remembered to re-run the script, which tests the
    // environment rather than the code and fails every fresh database for a reason unrelated to the change
    // being made.
    private async Task<VideoGameReferenceModel> CreateReferenceAsync(IVideoGameReferenceRepository repository, VideoGameReferenceModel model)
    {
        var created = await repository.UpsertAsync(model);
        TrackDocument("videogame_reference", created.Id);
        return created;
    }
}
