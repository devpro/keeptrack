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
/// Exercises <see cref="IVideoGameReferenceRepository.FindByTitleYearAsync"/> and <see cref="IVideoGameReferenceRepository.FindByTitleAsync"/> against real MongoDB,
/// the <c>ElemMatch</c> over <c>MatchedAliases</c> of <c>TvShowReferenceRepositoryTest</c>, for video games.
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
    /// A game is identified by its title <i>and</i> year, so a document with no year has no complete key to record,
    /// and a title-only alias would answer every later lookup for that title, whatever its year.
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
        // video games are the one domain where a single reference legitimately carries two providers' ids: it was linked through RAWG and later adopted an IGDB one.
        // Both must resolve to the same document, or a re-resolve through the other provider would create a duplicate instead of updating this one.
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
        // and an id belonging to the other provider's number space must not match: they are both plain integers, so nothing but the provider key tells them apart
        (await repository.FindByExternalIdAsync("igdb", rawgId)).Should().BeNull();
    }

    /// <summary>
    /// A tenant recording "Resident Evil 2" with <b>no year</b> must not be linked to whichever same-titled reference document the database returns first.
    /// <para>
    /// The rule: with no year nothing chooses between same-titled works, so nothing is chosen.
    /// It is the yearless half of the "Road House" rule, which stops a known year being ignored.
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
    /// The exception that keeps the rule above useful: one candidate for the title is not a guess, it is the answer.
    /// A yearless tenant item still links when the database holds exactly one work by that name, the ordinary case and the reason the title-only lookup exists.
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
    /// The other half of what the owner reported: a tenant who <i>did</i> supply the year must get the game from that year, not whichever same-titled document sorts first.
    /// This is what makes "a supplied year gets an immediate match" a real contract rather than luck.
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

    // No "a duplicate external id is rejected" test here, for igdb or rawg, nor on the other four reference collections.
    // The guarantee is real (a unique partial index per provider key in scripts/mongodb-create-index.js), but this suite creates no indexes, which that script applies out of band.
    // Such a test would pass or fail on whether someone re-ran the script, testing the environment rather than the code, and failing every fresh database.
    private async Task<VideoGameReferenceModel> CreateReferenceAsync(IVideoGameReferenceRepository repository, VideoGameReferenceModel model)
    {
        var created = await repository.UpsertAsync(model);
        TrackDocument("videogame_reference", created.Id);
        return created;
    }
}
