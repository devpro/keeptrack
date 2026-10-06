using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Real-MongoDB coverage for the periodic sync's "what to refresh next" query, which a mocked repository can't prove.
/// <para>
/// Two server-side behaviours carry the whole design.
/// A never-enriched document comes first, which the date comparison alone can't give: MongoDB compares within a type, so <c>$lte</c> against a date matches neither null nor an absent field.
/// The ordering makes the per-pass cap safe, since what a pass doesn't reach leads the next, or a collection larger than the cap would never refresh its tail.
/// </para>
/// <para>
/// Movie references stand in for all five domains, since the query lives once in <c>ReferenceStalenessQueries</c>, each repository only handing it a field expression.
/// </para>
/// </summary>
public class ReferenceStalenessRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindStaleAsync_ReturnsNeverEnrichedFirst_ThenLeastRecentlyEnriched()
    {
        var repository = Repository();
        var marker = NewMarker();
        var now = DateTime.UtcNow;

        // inserted newest-first, so passing would be impossible on insertion order alone
        await CreateAsync(repository, marker, "fresh", now.AddDays(-4));
        await CreateAsync(repository, marker, "oldest", now.AddDays(-30));
        await CreateAsync(repository, marker, "never", lastEnrichedAt: null);
        await CreateAsync(repository, marker, "middle", now.AddDays(-12));

        var stale = await MineAsync(repository, marker, now.AddDays(-3));

        stale.Select(r => Suffix(r.Title)).Should().Equal(["never", "oldest", "middle", "fresh"]);
    }

    [Fact]
    public async Task FindStaleAsync_ExcludesAnythingEnrichedSinceTheCutoff()
    {
        var repository = Repository();
        var marker = NewMarker();
        var now = DateTime.UtcNow;

        await CreateAsync(repository, marker, "stale", now.AddDays(-5));
        await CreateAsync(repository, marker, "recent", now.AddHours(-1));

        var stale = await MineAsync(repository, marker, now.AddDays(-3));

        stale.Select(r => Suffix(r.Title)).Should().Equal(["stale"]);
    }

    [Fact]
    public async Task FindStaleAsync_HonoursThePerPassCap_AndStillHandsBackTheStalestEnd()
    {
        var repository = Repository();
        var marker = NewMarker();
        var now = DateTime.UtcNow;
        await CreateAsync(repository, marker, "a", now.AddDays(-30));
        await CreateAsync(repository, marker, "b", now.AddDays(-20));
        await CreateAsync(repository, marker, "c", now.AddDays(-10));

        // asserted over the whole page rather than this test's own documents: the cap applies to the collection, which is shared and owner-less, so a parallel class's stale documents legitimately occupy part of it
        var page = await repository.FindStaleAsync(now.AddDays(-3), 2);

        page.Should().HaveCountLessThanOrEqualTo(2);
        // the property the cap depends on: a page is the *stalest* end of the collection, in order.
        // Without it, everything past the cap would be refreshed never rather than on the next pass.
        page.Select(r => r.LastEnrichedAt ?? DateTime.MinValue).Should().BeInAscendingOrder();
    }

    /// <summary>
    /// <c>FindStaleAsync</c> is collection-wide (reference documents are shared and owner-less), so a parallel class's documents can legitimately come back too.
    /// Filtering to this test's own marker keeps the ordering assertions exact without pretending the query is scoped.
    /// </summary>
    private static async Task<List<MovieReferenceModel>> MineAsync(IMovieReferenceRepository repository, string marker, DateTime cutoff)
    {
        var page = await repository.FindStaleAsync(cutoff, 10_000);
        return page.Where(r => r.Title.StartsWith(marker, StringComparison.Ordinal)).ToList();
    }

    private async Task CreateAsync(IMovieReferenceRepository repository, string marker, string suffix, DateTime? lastEnrichedAt)
    {
        var saved = await repository.UpsertAsync(new MovieReferenceModel
        {
            Title = $"{marker}-{suffix}",
            TitleNormalized = TitleNormalizer.Normalize($"{marker}-{suffix}"),
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            LastEnrichedAt = lastEnrichedAt
        });
        TrackDocument("movie_reference", saved.Id!);
    }

    private IMovieReferenceRepository Repository()
    {
        var scope = Factory.Services.CreateScope();
        TrackCleanup(() =>
        {
            scope.Dispose();
            return Task.CompletedTask;
        });
        return scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
    }

    private static string NewMarker() => $"Staleness {Guid.NewGuid():N}";

    private static string Suffix(string title) => title[(title.LastIndexOf('-') + 1)..];
}
