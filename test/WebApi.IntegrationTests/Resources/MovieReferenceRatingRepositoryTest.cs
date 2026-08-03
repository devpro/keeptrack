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
/// Real-MongoDB coverage for the reference-rating feature's repository behaviors, which mocks can't prove:
/// the <see cref="ListSort.ReferenceRating"/> sort ordering (with unrated items last), the two
/// denormalized-copy propagation paths (<c>SetReferenceLinkAsync</c> on link, <c>SetReferenceRatingAsync</c>
/// on refresh and the batched <c>SetReferenceRatingsAsync</c> the admin recompute writes through), the
/// projected, id-cursor-paged <c>FindRatingsAsync</c> that feeds it, and that the reference document's
/// <c>Ratings</c>/<c>RatingsCheckedAt</c> dictionaries round-trip through BSON.
/// Each test uses its own random owner id so parallel runs can't interfere.
/// </summary>
public class MovieReferenceRatingRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindAllAsync_SortsByReferenceRating_BestFirstWithUnratedLast()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieRepository>();
        var ownerId = $"refrating-sort-{Guid.NewGuid():N}";

        await CreateMovieAsync(repository, NewMovie(ownerId, "Middle", referenceRating: 6.5));
        await CreateMovieAsync(repository, NewMovie(ownerId, "Unrated", referenceRating: null));
        await CreateMovieAsync(repository, NewMovie(ownerId, "Best", referenceRating: 9.1));

        var byReferenceRating = await repository.FindAllAsync(ownerId, 1, 10, null, NewMovie(ownerId, ""), ListSort.ReferenceRating);
        byReferenceRating.Items.Select(m => m.Title).Should().Equal(["Best", "Middle", "Unrated"],
            "the reference-rating sort is best-first with items that have no linked rating last");
    }

    [Fact]
    public async Task SetReferenceLinkAsync_StampsTheDenormalizedRating_OnlyOnUnlinkedMatches()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieRepository>();
        var ownerId = $"refrating-link-{Guid.NewGuid():N}";
        // SetReferenceLinkAsync matches by (title, year) across every owner by design, so a fixed title
        // would also rewrite anyone else's movie of that name in the shared test database - the one place a
        // random owner id isn't enough to isolate this test.
        var title = $"The Matrix {Guid.NewGuid():N}";

        var unlinked = await CreateMovieAsync(repository, NewMovie(ownerId, title, year: 1999));
        var alreadyLinked = await CreateMovieAsync(repository, NewMovie(ownerId, title, year: 1999, referenceId: "pre-existing"));

        await repository.SetReferenceLinkAsync(title, 1999, "reference-1", title, 1999, 8.2, 10);

        var reloadedUnlinked = await repository.FindOneAsync(unlinked.Id!, ownerId);
        reloadedUnlinked!.ReferenceId.Should().Be("reference-1");
        reloadedUnlinked.ReferenceRating.Should().Be(8.2);
        reloadedUnlinked.ReferenceRatingScale.Should().Be(10);

        // an already-linked document is left untouched by the link propagation (UnresolvedFilter)
        var reloadedLinked = await repository.FindOneAsync(alreadyLinked.Id!, ownerId);
        reloadedLinked!.ReferenceId.Should().Be("pre-existing");
        reloadedLinked.ReferenceRating.Should().BeNull();
    }

    [Fact]
    public async Task SetReferenceRatingAsync_RepropagatesToEveryAlreadyLinkedMovie()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieRepository>();
        var ownerId = $"refrating-refresh-{Guid.NewGuid():N}";
        // unique per run: SetReferenceRatingAsync propagates by reference id across every owner, so a fixed
        // literal would also hit leftovers from an earlier run and break the exact modified-count assertion.
        var referenceId = $"reference-{Guid.NewGuid():N}";

        var linkedA = await CreateMovieAsync(repository, NewMovie(ownerId, "Alien", referenceId: referenceId, referenceRating: 7.0));
        var linkedB = await CreateMovieAsync(repository, NewMovie(ownerId, "Alien", referenceId: referenceId, referenceRating: 7.0));
        var other = await CreateMovieAsync(repository, NewMovie(ownerId, "Other", referenceId: $"reference-other-{Guid.NewGuid():N}", referenceRating: 5.0));

        var modified = await repository.SetReferenceRatingAsync(referenceId, 8.4, 10, "tmdb");
        modified.Should().Be(2);

        (await repository.FindOneAsync(linkedA.Id!, ownerId))!.ReferenceRating.Should().Be(8.4);
        (await repository.FindOneAsync(linkedB.Id!, ownerId))!.ReferenceRating.Should().Be(8.4);
        // a movie linked to a different reference is untouched
        (await repository.FindOneAsync(other.Id!, ownerId))!.ReferenceRating.Should().Be(5.0);
    }

    [Fact]
    public async Task MovieReferenceRatings_RoundTripThroughBson()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();

        var saved = await referenceRepository.UpsertAsync(new MovieReferenceModel
        {
            Title = $"Round Trip {Guid.NewGuid():N}",
            TitleNormalized = "placeholder",
            Year = 2001,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 7.8, Scale = 10, Count = 4321 } }
        });
        TrackCleanup(() => referenceRepository.DeleteAsync(saved.Id!));

        var reloaded = await referenceRepository.FindByIdAsync(saved.Id!);
        reloaded!.Ratings.Should().ContainKey("tmdb");
        reloaded.Ratings["tmdb"].Value.Should().Be(7.8);
        reloaded.Ratings["tmdb"].Scale.Should().Be(10);
        reloaded.Ratings["tmdb"].Count.Should().Be(4321);
    }

    [Fact]
    public async Task SetReferenceRatingAsync_StampsTheSourceAlongsideTheValue()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieRepository>();
        var ownerId = $"refsource-stamp-{Guid.NewGuid():N}";
        var referenceId = $"reference-{Guid.NewGuid():N}";
        var movie = await CreateMovieAsync(repository, NewMovie(ownerId, "Heat", referenceId: referenceId, referenceRating: 7.0));

        await repository.SetReferenceRatingAsync(referenceId, 8.4, 10, "imdb");

        var reloaded = await repository.FindOneAsync(movie.Id!, ownerId);
        reloaded!.ReferenceRatingSource.Should().Be("imdb", "the source travels with the value it was computed from");
    }

    [Fact]
    public async Task CountLinkedOnOtherRatingSourceAsync_CountsItemsOnAnotherSource_AndItemsNeverStampedAtAll()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieRepository>();
        var ownerId = $"refsource-count-{Guid.NewGuid():N}";
        var referenceId = $"reference-{Guid.NewGuid():N}";

        // three shapes that must all be distinguished: on the selected source, on another one, and one that
        // predates the stamp entirely - the last is the one a $ne filter can silently miss, since a missing
        // field is not "not equal" in every query language
        var onTmdb = await CreateMovieAsync(repository, NewMovie(ownerId, "A", referenceId: referenceId, referenceRating: 7.0));
        await repository.SetReferenceRatingAsync(referenceId, 7.0, 10, "tmdb");
        var onImdb = await CreateMovieAsync(repository, NewMovie(ownerId, "B", referenceId: $"other-{Guid.NewGuid():N}", referenceRating: 8.0));
        await repository.SetReferenceRatingAsync(onImdb.ReferenceId!, 8.0, 10, "imdb");
        var neverStamped = await CreateMovieAsync(repository, NewMovie(ownerId, "C", referenceId: $"unstamped-{Guid.NewGuid():N}", referenceRating: 6.0));

        var before = await repository.CountLinkedOnOtherRatingSourceAsync("tmdb");
        before.Should().BeGreaterThanOrEqualTo(2, "the imdb-stamped item and the never-stamped one both need re-stamping");

        await repository.SetReferenceRatingAsync(onImdb.ReferenceId!, 8.0, 10, "tmdb");
        await repository.SetReferenceRatingAsync(neverStamped.ReferenceId!, 6.0, 10, "tmdb");

        // once everything this test created is on the selected source, none of it is counted any more - which
        // is what lets the admin recompute report "nothing to do" and skip its whole pass
        (await repository.CountLinkedOnOtherRatingSourceAsync("tmdb")).Should().Be(before - 2);
        (await repository.FindOneAsync(onTmdb.Id!, ownerId))!.ReferenceRatingSource.Should().Be("tmdb");
    }

    [Fact]
    public async Task SetReferenceRatingsAsync_ReStampsEveryReferenceInTheBatch_InOneBulkWrite()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieRepository>();
        var ownerId = $"refrating-bulk-{Guid.NewGuid():N}";
        // unique per run for the same reason as SetReferenceRatingAsync's test: propagation is by reference
        // id across every owner, so a fixed literal would also catch leftovers and break the exact counts
        var firstReferenceId = $"reference-{Guid.NewGuid():N}";
        var secondReferenceId = $"reference-{Guid.NewGuid():N}";
        var untouchedReferenceId = $"reference-{Guid.NewGuid():N}";

        var firstA = await CreateMovieAsync(repository, NewMovie(ownerId, "Heat", referenceId: firstReferenceId, referenceRating: 7.0));
        var firstB = await CreateMovieAsync(repository, NewMovie(ownerId, "Heat", referenceId: firstReferenceId, referenceRating: 7.0));
        var second = await CreateMovieAsync(repository, NewMovie(ownerId, "Casino", referenceId: secondReferenceId, referenceRating: 6.0));
        var untouched = await CreateMovieAsync(repository, NewMovie(ownerId, "Other", referenceId: untouchedReferenceId, referenceRating: 5.0));

        var modified = await repository.SetReferenceRatingsAsync(
        [
            (firstReferenceId, 8.4, 10, "imdb"),
            (secondReferenceId, null, null, "imdb")
        ]);

        // one bulk write, but each entry still re-stamps *all* of its reference's linked items - which is what
        // keeps a recompute's cost flat as the number of users grows
        modified.Should().Be(3);
        (await repository.FindOneAsync(firstA.Id!, ownerId))!.ReferenceRating.Should().Be(8.4);
        (await repository.FindOneAsync(firstB.Id!, ownerId))!.ReferenceRating.Should().Be(8.4);

        // a reference the selected source has no value for is still stamped with that source, value cleared
        var reloadedSecond = await repository.FindOneAsync(second.Id!, ownerId);
        reloadedSecond!.ReferenceRating.Should().BeNull();
        reloadedSecond.ReferenceRatingSource.Should().Be("imdb");

        (await repository.FindOneAsync(untouched.Id!, ownerId))!.ReferenceRating.Should().Be(5.0);
    }

    [Fact]
    public async Task FindRatingsAsync_ReadsRatingsOnly_AndPagesForwardFromTheIdCursor()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();

        var first = await CreateReferenceAsync(referenceRepository, tmdb: 7.1);
        var second = await CreateReferenceAsync(referenceRepository, tmdb: 7.2);
        var third = await CreateReferenceAsync(referenceRepository, tmdb: 7.3);

        // ObjectIds are monotonic, so these three are the tail of the collection and the cursor should walk
        // straight from the first to the other two. Assertions stay relative: this is the shared reference
        // collection, and other documents (including other tests') legitimately share it.
        var page = await referenceRepository.FindRatingsAsync(first.Id, 100);

        page.Select(r => r.Id).Should().BeInAscendingOrder("the cursor relies on _id order to page without gaps or repeats");
        page.Select(r => r.Id).Should().NotContain(first.Id, "a cursor page starts strictly after the id it was given");
        page.Should().Contain(r => r.Id == second.Id).And.Contain(r => r.Id == third.Id);

        // the projection has to carry the ratings themselves, or the recompute would re-stamp everything null
        var projected = page.Single(r => r.Id == third.Id).Ratings;
        projected["tmdb"].Value.Should().Be(7.3);
        projected["tmdb"].Scale.Should().Be(10);

        // and a limit still applies on top of the cursor
        (await referenceRepository.FindRatingsAsync(first.Id, 1)).Should().ContainSingle();
    }

    [Fact]
    public async Task MovieReferenceRatingsCheckedAt_RoundTripsThroughBson_AsUtc()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
        var attemptedAt = DateTime.UtcNow;

        var saved = await referenceRepository.UpsertAsync(new MovieReferenceModel
        {
            Title = $"Attempt Stamp {Guid.NewGuid():N}",
            TitleNormalized = "placeholder",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            RatingsCheckedAt = new Dictionary<string, DateTime> { ["imdb"] = attemptedAt }
        });
        TrackCleanup(() => referenceRepository.DeleteAsync(saved.Id!));

        var reloaded = await referenceRepository.FindByIdAsync(saved.Id!);
        // BSON dates are millisecond-precision, so the stamp comes back rounded - close enough for a 90-day
        // window, but it must come back as UTC: the re-attempt check subtracts it from DateTime.UtcNow, and a
        // value read back as Local or Unspecified would silently shift that window by the host's offset.
        reloaded!.RatingsCheckedAt["imdb"].Should().BeCloseTo(attemptedAt, TimeSpan.FromMilliseconds(1));
        reloaded.RatingsCheckedAt["imdb"].Kind.Should().Be(DateTimeKind.Utc);
    }

    private async Task<MovieReferenceModel> CreateReferenceAsync(IMovieReferenceRepository repository, double tmdb)
    {
        var saved = await repository.UpsertAsync(new MovieReferenceModel
        {
            Title = $"Ratings Page {Guid.NewGuid():N}",
            TitleNormalized = "placeholder",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() },
            Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = tmdb, Scale = 10, Count = 10 } }
        });
        TrackCleanup(() => repository.DeleteAsync(saved.Id!));
        return saved;
    }

    private async Task<MovieModel> CreateMovieAsync(IMovieRepository repository, MovieModel movie)
    {
        var created = await repository.CreateAsync(movie);
        TrackCleanup(() => repository.DeleteAsync(created.Id!, movie.OwnerId));
        return created;
    }

    private static MovieModel NewMovie(string ownerId, string title, int? year = null, string? referenceId = null, double? referenceRating = null) => new()
    {
        OwnerId = ownerId,
        Title = title,
        Year = year,
        ReferenceId = referenceId,
        ReferenceRating = referenceRating,
        ReferenceRatingScale = referenceRating is null ? null : 10,
    };
}
