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
/// against real MongoDB - both now match against every entry in <c>MatchedAliases</c> (an <c>ElemMatch</c>
/// filter over the embedded (title, year) array, backing a compound multikey index), not just the
/// document's own canonical <c>TitleNormalized</c>/<c>Year</c>. This is exactly the kind of hand-written
/// Mongo filter that has hidden real bugs before (see docs/code-quality-findings.md), so it's verified
/// against a real database, not mocks.
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
        // regression: a single top-level Year scalar AND-ed against the title-array-contains filter would
        // reject a tenant whose recorded year genuinely differs from whichever year happens to be this
        // document's own canonical one - year now travels with its specific title variant instead.
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
        // Regression: a null Creator (TV show/movie/video game have no creator dimension) has to round-trip
        // as a real null, not "". Getting this wrong once let a null Creator silently become "" on save,
        // which broke MergeMatchedAliases' in-memory dedup comparison and duplicated an alias on every
        // re-resolve/re-refresh (confirmed against a real video game reference, RAWG's "God of War", that had
        // accumulated an exact duplicate this way - see scripts/dedupe-matched-aliases.js). Mapperly (the
        // current mapper) preserves nulls by default, so this now guards a structural property rather than a
        // configuration one - and only a real MongoDB round-trip can check it at all, since a mocked
        // repository never exercises the actual mapper/BSON serialization behavior.
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
    /// Upserts a reference and registers it for deletion in the same step, so no test body can create one
    /// without it being cleaned up.
    /// </summary>
    private async Task<TvShowReferenceModel> CreateReferenceAsync(ITvShowReferenceRepository repository, TvShowReferenceModel model)
    {
        var created = await repository.UpsertAsync(model);
        TrackDocument("tvshow_reference", created.Id);
        return created;
    }
}
