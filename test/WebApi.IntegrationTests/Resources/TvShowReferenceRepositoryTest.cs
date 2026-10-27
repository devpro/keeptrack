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
/// Exercises <see cref="ITvShowReferenceRepository.FindByTitleYearAsync"/> and <see cref="ITvShowReferenceRepository.FindByTitleAsync"/> against real MongoDB.
/// Both match every entry in <c>MatchedAliases</c> (an <c>ElemMatch</c> over the embedded (title, year) array, backed by a compound multikey index),
/// not only the canonical <c>TitleNormalized</c> and <c>Year</c>.
/// A hand-written Mongo filter of this kind hides bugs (see docs/data-model.md), so it is verified against a real database, not mocks.
/// </summary>
public class TvShowReferenceRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindByTitleYearAsync_MatchesAnAlternateTitle_NotJustTheCanonicalOne()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var alternateTitle = $"Alternate Title {Guid.NewGuid()}";
        const int year = 2005;

        var created = await CreateReferenceAsync(repository, new TvShowReferenceModel
        {
            Title = "Canonical Title",
            TitleNormalized = "canonical title",
            Year = year,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = year }]
        });

        // case-insensitive: normalization lower-cases before comparing
        var found = await repository.FindByTitleYearAsync(alternateTitle.ToUpperInvariant(), year);

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    [Fact]
    public async Task FindByTitleYearAsync_MatchesAnAliasWhoseConfirmedYearDiffersFromTheDocumentsOwnCanonicalYear()
    {
        // A top-level Year AND-ed with the title filter would reject a tenant whose year differs from the document's canonical one, so the year travels with its title variant.
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var alternateTitle = $"Alternate Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new TvShowReferenceModel
        {
            Title = "Canonical Title",
            TitleNormalized = "canonical title",
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
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
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var alternateTitle = $"Alternate Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new TvShowReferenceModel
        {
            Title = "Canonical Title",
            TitleNormalized = "canonical title",
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2005 }]
        });

        var found = await repository.FindByTitleAsync(alternateTitle);

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    [Fact]
    public async Task UpsertAsync_PersistsANullCreator_AsAnActualBsonNullNotAnEmptyString()
    {
        // A null Creator (TV show, movie and video game have no creator) round-trips as a real null, not "".
        // A null saved as "" breaks MergeMatchedAliases' in-memory dedup and duplicates an alias on every re-resolve (see scripts/dedupe-matched-aliases.js).
        // Mapperly preserves nulls by default, and only a real MongoDB round trip checks it, since a mocked repository never exercises the mapper and BSON serialization.
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Null Creator Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new TvShowReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2010,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = title.ToLowerInvariant(), Year = 2010, Creator = null }]
        });

        var collection = scope.ServiceProvider.GetRequiredService<IMongoDatabase>().GetCollection<TvShowReference>("tvshow_reference");
        var stored = await collection.Find(x => x.Id == created.Id).FirstOrDefaultAsync(TestContext.Current.CancellationToken);

        stored.MatchedAliases.Should().ContainSingle(m => m.Creator == null);
    }

    [Fact]
    public async Task UpsertAsync_AlwaysIncludesTheCanonicalTitleAndYearInMatchedAliases_EvenIfTheCallerForgot()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Canonical Only Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new TvShowReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2010,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() }
        });

        var found = await repository.FindByTitleAsync(title);

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    /// <summary>
    /// The yearless title lookup refuses to choose between same-titled works here too, not only for video games.
    /// The rule lives once in <c>ReferenceAliasQueries.FindSingleMatchAsync</c>, which TV shows reach through the same title-only fallback.
    /// Two shows sharing a name is ordinary (a revival, a remake), and with no year there is nothing to tell them apart with.
    /// </summary>
    [Fact]
    public async Task FindByTitleAsync_MatchesNothing_WhenSeveralReferencesShareTheTitleAndOnlyTheYearCouldTellThemApart()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Shared Show Title {Guid.NewGuid()}";

        foreach (var year in (int[])[1990, 2024])
        {
            await CreateReferenceAsync(repository, new TvShowReferenceModel
            {
                Title = title,
                TitleNormalized = title.ToLowerInvariant(),
                Year = year,
                ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() }
            });
        }

        var found = await repository.FindByTitleAsync(title);

        found.Should().BeNull("nothing but the year separates two shows called \"{0}\", and no year was given", title);
    }

    /// <summary>
    /// Upserts a reference and registers it for deletion in the same step, so no test body can create one without it being cleaned up.
    /// </summary>
    private async Task<TvShowReferenceModel> CreateReferenceAsync(ITvShowReferenceRepository repository, TvShowReferenceModel model)
    {
        var created = await repository.UpsertAsync(model);
        TrackDocument("tvshow_reference", created.Id);
        return created;
    }
}
