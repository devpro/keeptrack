using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

public class TvTimeImportResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task ImportTvTime_UpsertsShowsEpisodesAndMovies_AndIsIdempotent()
    {
        await Authenticate();

        var zip = TvTimeFixtureZipBuilder.Build();

        var firstJob = await PostFileAsync<ImportJobDto>("/api/import/tv-time", "file", zip, "gdpr-data.zip", HttpStatusCode.Accepted);
        var firstResult = await PollForResultAsync(firstJob.JobId);
        // ShowTitle (from followed_tv_show.csv) + OrphanShowTitle (has watch history but is absent from
        // followed_tv_show.csv - the importer must create it anyway, not skip it)
        firstResult.ShowsCreated.Should().Be(2);
        // 4 for ShowTitle (2 from seen_episode_source.csv + 1 from tracking-prod-records.csv + 1 from
        // tracking-prod-records-v2.csv) + 1 for OrphanShowTitle (tracking-prod-records-v2.csv only)
        firstResult.EpisodesCreated.Should().Be(5);
        firstResult.MoviesCreated.Should().Be(1);
        // user_tv_show_data.csv reports 5 episodes seen, but only 4 got a watch date from the sources above
        firstResult.Warnings.Should().Contain(w => w.Contains(TvTimeFixtureZipBuilder.ShowTitle) && w.Contains("4 of 5"));

        try
        {
            var shows = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.ShowTitle)}");
            var show = shows.Items.Should().ContainSingle().Subject;
            show.Rating.Should().Be(4.5f);
            show.IsFavorite.Should().BeTrue();
            show.Notes.Should().Contain("Great show");

            var episodes = await GetAsync<PagedResult<EpisodeDto>>($"/api/episodes?TvShowId={show.Id}");
            episodes.Items.Should().HaveCount(4);
            episodes.Items.Should().Contain(e => e.SeasonNumber == 1 && e.EpisodeNumber == 1 && e.Notes == "Great pilot");
            episodes.Items.Should().Contain(e => e.SeasonNumber == 1 && e.EpisodeNumber == 3);
            episodes.Items.Should().Contain(e => e.SeasonNumber == 2 && e.EpisodeNumber == 1);

            // the real-world bug this guards against: a show with genuine watch history but no
            // followed_tv_show.csv row must still be created, with its own rating applied by id, and
            // its episode imported - not silently skipped with a "wasn't found" warning.
            var orphanShows = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.OrphanShowTitle)}");
            var orphanShow = orphanShows.Items.Should().ContainSingle().Subject;
            orphanShow.Rating.Should().Be(3.5f);

            var orphanEpisodes = await GetAsync<PagedResult<EpisodeDto>>($"/api/episodes?TvShowId={orphanShow.Id}");
            orphanEpisodes.Items.Should().ContainSingle(e => e.SeasonNumber == 1 && e.EpisodeNumber == 1);

            var movies = await GetAsync<PagedResult<MovieDto>>($"/api/movies?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.MovieTitle)}");
            var movie = movies.Items.Should().ContainSingle().Subject;
            movie.IsFavorite.Should().BeTrue();

            // re-importing the same export must upsert, not duplicate
            var secondJob = await PostFileAsync<ImportJobDto>("/api/import/tv-time", "file", zip, "gdpr-data.zip", HttpStatusCode.Accepted);
            var secondResult = await PollForResultAsync(secondJob.JobId);
            secondResult.ShowsCreated.Should().Be(0);
            secondResult.ShowsUpdated.Should().Be(2);
            secondResult.EpisodesCreated.Should().Be(0);
            secondResult.EpisodesUpdated.Should().Be(5);
            secondResult.MoviesCreated.Should().Be(0);
            secondResult.MoviesUpdated.Should().Be(1);

            var showsAfterReimport = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.ShowTitle)}");
            showsAfterReimport.Items.Should().ContainSingle();

            var orphanShowsAfterReimport = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.OrphanShowTitle)}");
            orphanShowsAfterReimport.Items.Should().ContainSingle();
        }
        finally
        {
            foreach (var title in new[] { TvTimeFixtureZipBuilder.ShowTitle, TvTimeFixtureZipBuilder.OrphanShowTitle })
            {
                var shows = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(title)}");
                foreach (var show in shows.Items)
                {
                    var episodes = await GetAsync<PagedResult<EpisodeDto>>($"/api/episodes?TvShowId={show.Id}");
                    foreach (var episode in episodes.Items.Where(e => e.Id is not null))
                    {
                        await DeleteAsync($"/api/episodes/{episode.Id}");
                    }

                    await DeleteAsync($"/api/tv-shows/{show.Id}");
                }
            }

            var movies = await GetAsync<PagedResult<MovieDto>>($"/api/movies?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.MovieTitle)}");
            foreach (var movie in movies.Items.Where(m => m.Id is not null))
            {
                await DeleteAsync($"/api/movies/{movie.Id}");
            }
        }
    }

    private async Task<ImportResultDto> PollForResultAsync(Guid jobId)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var status = await GetAsync<ImportJobStatusDto>($"/api/import/tv-time/{jobId}");
            switch (status.Stage)
            {
                case ImportStage.Completed:
                    status.Result.Should().NotBeNull();
                    return status.Result!;
                case ImportStage.Failed:
                    throw new InvalidOperationException($"Import job failed: {status.ErrorMessage}");
                default:
                    await Task.Delay(100);
                    break;
            }
        }

        throw new TimeoutException("Import job did not complete in time.");
    }
}
