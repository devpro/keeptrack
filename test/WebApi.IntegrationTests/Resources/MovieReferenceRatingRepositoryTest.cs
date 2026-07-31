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
/// denormalized-copy propagation paths (<c>SetReferenceLinkAsync</c> on link and <c>SetReferenceRatingAsync</c>
/// on refresh), and that the reference document's <c>Ratings</c> dictionary round-trips through BSON.
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

        var modified = await repository.SetReferenceRatingAsync(referenceId, 8.4, 10);
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
