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

    /// <summary>
    /// A game is identified by its title <i>and</i> its year, so a document with no year has no complete key to record - and the title-only alias that used to be written for it answered every later lookup for that title, whatever year it carried.
    /// IGDB holds eight games named exactly "Resident Evil 2".
    /// </summary>
    [Fact]
    public async Task UpsertAsync_RecordsNoCanonicalAlias_WhenTheDocumentHasNoYear()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Yearless Game Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new VideoGameReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            ExternalIds = new Dictionary<string, string> { ["igdb"] = TestExternalId.New() }
        });

        var found = await repository.FindByIdAsync(created.Id!);

        found.Should().NotBeNull();
        found!.MatchedAliases.Should().BeEmpty();
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

    /// <summary>
    /// <b>Desired behaviour, reported from the running app on 2026-08-16 and not yet implemented.</b>
    /// <para>
    /// A tenant recording "Resident Evil 2" with <b>no year</b> must not be linked to whichever same-titled
    /// reference document the database happens to return first. Today it is: <c>FindByTitleAsync</c> is a
    /// <c>FirstOrDefaultAsync</c> over an unsorted, unbounded match, so the owner saw a yearless "Resident Evil
    /// 2" silently adopt the 2019 remake's reference - and then, after deleting that link, adopt it again.
    /// </para>
    /// <para>
    /// The rule: with no year there is nothing to choose between same-titled works with, so nothing is chosen.
    /// This is the half of the "Road House" finding that was never closed - that fix stopped a *known* year
    /// being ignored, and left the yearless case guessing.
    /// </para>
    /// </summary>
    [Fact]
    public async Task FindByTitleAsync_MatchesNothing_WhenSeveralReferencesShareTheTitleAndOnlyTheYearCouldTellThemApart()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Resident Evil 2 {Guid.NewGuid()}";

        await CreateReferenceAsync(repository, SameTitledGame(title, 1998));
        await CreateReferenceAsync(repository, SameTitledGame(title, 2019));

        var found = await repository.FindByTitleAsync(title);

        found.Should().BeNull("nothing but the year separates two games called \"{0}\", and no year was given", title);
    }

    /// <summary>
    /// The exception that keeps the rule above useful: one candidate for the title is not a guess, it is the
    /// answer. A yearless tenant item must still link when the database holds exactly one work by that name -
    /// which is the ordinary case and the reason the title-only lookup exists at all.
    /// </summary>
    [Fact]
    public async Task FindByTitleAsync_StillMatches_WhenOnlyOneReferenceCarriesTheTitle()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Code Vein {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, SameTitledGame(title, 2019));

        var found = await repository.FindByTitleAsync(title);

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    /// <summary>
    /// The other half of what the owner reported: a tenant who <i>did</i> supply the year must get the game
    /// from that year, not whichever same-titled document sorts first. This is what makes "supply a year and
    /// you get an immediate match" a real contract rather than luck.
    /// </summary>
    [Fact]
    public async Task FindByTitleYearAsync_PicksTheReferenceFromTheRequestedYear_WhenSeveralShareTheTitle()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Resident Evil 2 {Guid.NewGuid()}";

        await CreateReferenceAsync(repository, SameTitledGame(title, 1998));
        var remake = await CreateReferenceAsync(repository, SameTitledGame(title, 2019));

        var found = await repository.FindByTitleYearAsync(title, 2019);

        found.Should().NotBeNull();
        found!.Id.Should().Be(remake.Id);
    }

    private static VideoGameReferenceModel SameTitledGame(string title, int year) => new()
    {
        Title = title,
        TitleNormalized = title.ToLowerInvariant(),
        Year = year,
        ExternalIds = new Dictionary<string, string> { ["igdb"] = TestExternalId.New() }
    };

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
