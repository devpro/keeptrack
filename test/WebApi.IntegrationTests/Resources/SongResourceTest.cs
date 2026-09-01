using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Bogus;
using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Basic full-cycle CRUD coverage for <c>Song</c>, same shape as <see cref="AlbumResourceTest"/>. Song
/// has no dedicated list page in the UI - it's created/managed only from within a playlist - but still
/// gets full CRUD via the API so the same song can be created once and reused across playlists.
/// </summary>
public class SongResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/songs";

    [Fact]
    public async Task SongResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var input = new Faker<SongDto>()
            .Rules((f, o) => { o.Title = f.Random.AlphaNumeric(14); o.Artist = f.Random.AlphaNumeric(8); })
            .Generate();
        var created = await CreateAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        created.Title = "New shiny title";
        await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

        var updated = await GetAsync<SongDto>($"/{ResourceEndpoint}/{created.Id}");
        updated.Should().BeEquivalentTo(created);

        var finalItems = await GetAsync<PagedResult<SongDto>>($"/{ResourceEndpoint}");
        var firstItem = finalItems.Items.FirstOrDefault(x => x.Id == updated.Id);
        firstItem.Should().NotBeNull();
        firstItem.Title.Should().Be(updated.Title);
    }

    [Fact]
    public async Task SongResourceCreate_PersistsAlbumLink_IsOk()
    {
        await Authenticate();

        var created = await CreateAsync($"/{ResourceEndpoint}", new SongDto { Title = "Time Is Running Out", Artist = "Muse", AlbumId = "some-album-id" });

        var fetched = await GetAsync<SongDto>($"/{ResourceEndpoint}/{created.Id}");
        fetched.AlbumId.Should().Be("some-album-id");
    }

    /// <summary>
    /// Backs <c>SongApiClient.GetOrCreateForTrackAsync</c>'s dedupe lookup - picking the same track twice
    /// must find the one already-created song for it, not create a duplicate. Two songs share an
    /// <c>AlbumId</c> here specifically to prove the filter matches on both fields together, not either alone.
    /// </summary>
    [Fact]
    public async Task SongResourceSearch_FiltersToMatchingAlbumIdAndTrackPosition_IsOk()
    {
        await Authenticate();

        const string albumId = "shared-album-id";
        var trackOne = await CreateAsync($"/{ResourceEndpoint}", new SongDto { Title = "Apocalypse Please", AlbumId = albumId, TrackPosition = "2" });
        var trackTwo = await CreateAsync($"/{ResourceEndpoint}", new SongDto { Title = "Time Is Running Out", AlbumId = albumId, TrackPosition = "3" });

        var results = await GetAsync<PagedResult<SongDto>>($"/{ResourceEndpoint}?AlbumId={albumId}&TrackPosition=3");

        results.Items.Should().ContainSingle(x => x.Id == trackTwo.Id);
        results.Items.Should().NotContain(x => x.Id == trackOne.Id);
    }
}
