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

        var firstResult = await PostFileAsync<ImportResultDto>("/api/import/tv-time", "file", zip, "gdpr-data.zip");
        firstResult.ShowsCreated.Should().Be(1);
        firstResult.EpisodesCreated.Should().Be(2);
        firstResult.MoviesCreated.Should().Be(1);

        try
        {
            var shows = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.ShowTitle)}");
            var show = shows.Items.Should().ContainSingle().Subject;
            show.Rating.Should().Be(4.5f);
            show.IsFavorite.Should().BeTrue();
            show.Notes.Should().Contain("Great show");

            var episodes = await GetAsync<PagedResult<EpisodeDto>>($"/api/episodes?TvShowId={show.Id}");
            episodes.Items.Should().HaveCount(2);
            episodes.Items.Should().Contain(e => e.SeasonNumber == 1 && e.EpisodeNumber == 1 && e.Notes == "Great pilot");

            var movies = await GetAsync<PagedResult<MovieDto>>($"/api/movies?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.MovieTitle)}");
            var movie = movies.Items.Should().ContainSingle().Subject;
            movie.IsFavorite.Should().BeTrue();

            // re-importing the same export must upsert, not duplicate
            var secondResult = await PostFileAsync<ImportResultDto>("/api/import/tv-time", "file", zip, "gdpr-data.zip");
            secondResult.ShowsCreated.Should().Be(0);
            secondResult.ShowsUpdated.Should().Be(1);
            secondResult.EpisodesCreated.Should().Be(0);
            secondResult.EpisodesUpdated.Should().Be(2);
            secondResult.MoviesCreated.Should().Be(0);
            secondResult.MoviesUpdated.Should().Be(1);

            var showsAfterReimport = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.ShowTitle)}");
            showsAfterReimport.Items.Should().ContainSingle();
        }
        finally
        {
            var shows = await GetAsync<PagedResult<TvShowDto>>($"/api/tv-shows?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.ShowTitle)}");
            foreach (var show in shows.Items)
            {
                var episodes = await GetAsync<PagedResult<EpisodeDto>>($"/api/episodes?TvShowId={show.Id}");
                foreach (var episode in episodes.Items.Where(e => e.Id is not null))
                {
                    await DeleteAsync($"/api/episodes/{episode.Id}");
                }

                await DeleteAsync($"/api/tv-shows/{show.Id}");
            }

            var movies = await GetAsync<PagedResult<MovieDto>>($"/api/movies?search={Uri.EscapeDataString(TvTimeFixtureZipBuilder.MovieTitle)}");
            foreach (var movie in movies.Items.Where(m => m.Id is not null))
            {
                await DeleteAsync($"/api/movies/{movie.Id}");
            }
        }
    }
}
