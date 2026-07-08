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
/// Basic full-cycle CRUD coverage for <c>Playlist</c>, same shape as <see cref="AlbumResourceTest"/>,
/// plus a check that <see cref="PlaylistDto.SongIds"/> round-trips its order through a PUT - this is the
/// field that actually encodes playback order, so a bug here would silently scramble every playlist.
/// </summary>
public class PlaylistResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/playlists";

    [Fact]
    public async Task PlaylistResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var initialItems = await GetAsync<PagedResult<PlaylistDto>>($"/{ResourceEndpoint}");

        var input = new Faker<PlaylistDto>()
            .Rules((f, o) => { o.Title = f.Random.AlphaNumeric(14); })
            .Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Title = "New shiny title";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<PlaylistDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<PlaylistDto>>($"/{ResourceEndpoint}");
            finalItems.TotalCount.Should().BeGreaterThan(initialItems.TotalCount);
            var firstItem = finalItems.Items.FirstOrDefault(x => x.Id == updated.Id);
            firstItem.Should().NotBeNull();
            firstItem.Title.Should().Be(updated.Title);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task PlaylistResourceUpdate_PersistsSongIdsInOrder_IsOk()
    {
        await Authenticate();

        var created = await PostAsync($"/{ResourceEndpoint}", new PlaylistDto { Title = "Order Test Playlist" });

        try
        {
            created.SongIds = ["song-c", "song-a", "song-b"];
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<PlaylistDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.SongIds.Should().ContainInOrder("song-c", "song-a", "song-b");

            created.SongIds = ["song-a", "song-b"];
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var afterRemoval = await GetAsync<PlaylistDto>($"/{ResourceEndpoint}/{created.Id}");
            afterRemoval.SongIds.Should().ContainInOrder("song-a", "song-b");
            afterRemoval.SongIds.Should().HaveCount(2);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
