using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Import;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import;

/// <summary>
/// The bug these tests guard: shows/movies used to be matched by title, but reference enrichment
/// rewrites the stored Title to a provider's canonical name after the first import - so re-importing the
/// same export no longer matched and created duplicates (which then cascaded to duplicated episodes under
/// the new show id). The fix stamps every imported record with a stable, enrichment-immutable TvTimeId
/// and matches on that.
/// </summary>
[Trait("Category", "UnitTests")]
public class TvTimeImportServiceIdempotencyTest
{
    private const string OwnerId = "owner-1";
    private const string ShowTitle = "Test Show";
    private const string MovieTitle = "Test Movie";

    [Fact]
    public async Task ReImport_AfterEnrichmentRenamedTitles_DoesNotDuplicate_AndSkipsExisting()
    {
        var shows = new FakeTvShowRepository();
        var movies = new FakeMovieRepository();
        var episodes = new FakeEpisodeRepository();
        var service = NewService(shows, movies, episodes);

        var zip = BuildZip();

        var first = await service.ImportAsync(new MemoryStream(zip), OwnerId);
        first.ShowsCreated.Should().Be(1);
        first.EpisodesCreated.Should().Be(2);
        first.MoviesCreated.Should().Be(1);
        first.ShowsSkipped.Should().Be(0);
        first.EpisodesSkipped.Should().Be(0);
        first.MoviesSkipped.Should().Be(0);

        // Simulate what reference enrichment does after the first import: it overwrites the stored Title
        // with the provider's canonical name. This is exactly what used to break title-based matching.
        shows.Single().Title = "Some Completely Different Canonical Show Name";
        movies.Single().Title = "Some Completely Different Canonical Movie Name";

        var second = await service.ImportAsync(new MemoryStream(zip), OwnerId);

        // Nothing new created, everything recognized as already present - and, crucially, no duplicates.
        second.ShowsCreated.Should().Be(0);
        second.EpisodesCreated.Should().Be(0);
        second.MoviesCreated.Should().Be(0);
        second.ShowsSkipped.Should().Be(1);
        second.EpisodesSkipped.Should().Be(2);
        second.MoviesSkipped.Should().Be(1);

        shows.Items.Should().HaveCount(1);
        movies.Items.Should().HaveCount(1);
        episodes.Items.Should().HaveCount(2);
    }

    [Fact]
    public async Task Import_AdoptsAPreExistingRecordThatHasNoTvTimeIdYet_InsteadOfDuplicating()
    {
        var shows = new FakeTvShowRepository();
        var movies = new FakeMovieRepository();
        var episodes = new FakeEpisodeRepository();

        // A record created by an import that predated stable-id matching: same title, but no TvTimeId.
        await shows.CreateAsync(new TvShowModel { OwnerId = OwnerId, Title = ShowTitle, TvTimeId = null });

        var service = NewService(shows, movies, episodes);

        var result = await service.ImportAsync(new MemoryStream(BuildZip()), OwnerId);

        result.ShowsCreated.Should().Be(0);
        result.ShowsSkipped.Should().Be(1);
        shows.Items.Should().HaveCount(1, "the pre-existing record is adopted, not duplicated");
        shows.Single().TvTimeId.Should().Be("100", "its stable id is back-filled so the next re-import matches by id");
    }

    private static TvTimeImportService NewService(
        FakeTvShowRepository shows, FakeMovieRepository movies, FakeEpisodeRepository episodes) =>
        new(shows, episodes, movies, new ThrowingScopeFactory(), NullLogger<TvTimeImportService>.Instance);

    /// <summary>
    /// A minimal but realistic export: a followed show carrying its TV Time id, two of its episodes in the
    /// id-less seen_episode_source.csv (which must still resolve to that show), and a movie discovered
    /// through a tracking watch event carrying its stable per-movie uuid.
    /// </summary>
    private static byte[] BuildZip()
    {
        var entries = new Dictionary<string, string>
        {
            ["followed_tv_show.csv"] = $"tv_show_id,tv_show_name\n100,{ShowTitle}\n",
            ["seen_episode_source.csv"] =
                "tv_show_name,episode_season_number,episode_number,created_at\n" +
                $"{ShowTitle},1,1,2020-01-02 00:00:00\n" +
                $"{ShowTitle},1,2,2020-01-03 00:00:00\n",
            ["tracking-prod-records.csv"] =
                "series_name,uuid,type,created_at,series_id,user_id,movie_name,entity_type,season_number,episode_number\n" +
                $",movie-uuid-1,watch,2020-01-07 00:00:00,,999,{MovieTitle},movie,,\n"
        };

        using var zipStream = new MemoryStream();
        using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                using var writer = new StreamWriter(archive.CreateEntry(name).Open(), Encoding.UTF8);
                writer.Write(content);
            }
        }

        return zipStream.ToArray();
    }

    /// <summary>The import fires a best-effort reference match on a background DI scope; this stands in for
    /// the scope factory and makes that fire-and-forget path a caught no-op, which the import tolerates.</summary>
    private sealed class ThrowingScopeFactory : IServiceScopeFactory
    {
        public IServiceScope CreateScope() => throw new InvalidOperationException("No DI scope in unit tests.");
    }

    private class InMemoryRepository<TModel>(Func<TModel, TModel, bool>? matchesInput = null)
        where TModel : class, IHasIdAndOwnerId
    {
        private readonly Func<TModel, TModel, bool> _matchesInput = matchesInput ?? ((_, _) => true);

        public List<TModel> Items { get; } = [];

        public TModel Single() => Items.Single();

        public Task<TModel?> FindOneAsync(string id, string ownerId) =>
            Task.FromResult(Items.FirstOrDefault(x => x.Id == id && x.OwnerId == ownerId));

        public Task<PagedResult<TModel>> FindAllAsync(string ownerId, int page, int pageSize, string? search, TModel input)
        {
            var items = Items.Where(x => x.OwnerId == ownerId && _matchesInput(x, input)).ToList();
            return Task.FromResult(new PagedResult<TModel>(items, items.Count, page, pageSize));
        }

        public Task<TModel> CreateAsync(TModel model)
        {
            model.Id ??= Guid.NewGuid().ToString();
            Items.Add(model);
            return Task.FromResult(model);
        }

        public Task<long> UpdateAsync(string id, TModel model, string ownerId)
        {
            var index = Items.FindIndex(x => x.Id == id && x.OwnerId == ownerId);
            if (index < 0) return Task.FromResult(0L);
            Items[index] = model;
            return Task.FromResult(1L);
        }

        public Task<long> DeleteAsync(string id, string ownerId) =>
            Task.FromResult((long)Items.RemoveAll(x => x.Id == id && x.OwnerId == ownerId));
    }

    private sealed class FakeTvShowRepository : InMemoryRepository<TvShowModel>, ITvShowRepository
    {
        public Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null) =>
            Task.FromResult(0L);

        public Task<IReadOnlyList<(string Title, int? Year)>> FindDistinctUnresolvedTitleYearsAsync() =>
            Task.FromResult<IReadOnlyList<(string, int?)>>([]);
    }

    private sealed class FakeMovieRepository : InMemoryRepository<MovieModel>, IMovieRepository
    {
        public Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null) =>
            Task.FromResult(0L);

        public Task<IReadOnlyList<(string Title, int? Year)>> FindDistinctUnresolvedTitleYearsAsync() =>
            Task.FromResult<IReadOnlyList<(string, int?)>>([]);
    }

    private sealed class FakeEpisodeRepository()
        : InMemoryRepository<EpisodeModel>((episode, input) => episode.TvShowId == input.TvShowId), IEpisodeRepository;
}
