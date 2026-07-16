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
/// Basic full-cycle CRUD coverage for the renamed <c>Album</c> type (formerly <c>MusicAlbum</c>) - closes
/// a gap flagged in docs/code-quality-findings.md ("MusicAlbum...still has none"), same shape as
/// <see cref="BookResourceTest"/>.
/// </summary>
public class AlbumResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/albums";

    [Fact]
    public async Task AlbumResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var input = new Faker<AlbumDto>()
            .Rules((f, o) => { o.Artist = f.Random.AlphaNumeric(8); o.Title = f.Random.AlphaNumeric(14); })
            .Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Title = "New shiny title";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<AlbumDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<AlbumDto>>($"/{ResourceEndpoint}");
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
    public async Task AlbumResourceUpdate_PersistsArtistChange_IsOk()
    {
        // regression test for a reported "editing the artist doesn't update the data" bug - full review of
        // AlbumDetail.razor/Albums.razor/AlbumApiClient/DataCrudControllerBase/both mapper layers found
        // no code-level cause (identical shape to Book's Author editing, which isn't reported as broken); this
        // locks in that a PUT changing only Artist persists correctly end-to-end.
        await Authenticate();

        var created = await PostAsync($"/{ResourceEndpoint}", new AlbumDto { Title = "Artist Update Test", Artist = "Original Artist" });

        try
        {
            created.Artist = "Updated Artist";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<AlbumDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Artist.Should().Be("Updated Artist");
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task AlbumResourceOwnedFilter_OnlyReturnsAlbumsWithOwnedVersions_IsOk()
    {
        await Authenticate();

        var title = $"OwnedTarget-{System.Guid.NewGuid():N}";
        var created = await PostAsync($"/{ResourceEndpoint}", new AlbumDto
        {
            Title = title,
            Artist = "Owned Filter Artist",
            // "owned" is derived from having at least one owned version, not a stored flag
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Physical, Price = 24.50m, Vendor = "Record store", Reference = "Vinyl reissue" }]
        });
        var notOwned = await PostAsync($"/{ResourceEndpoint}", new AlbumDto { Title = title, Artist = "Owned Filter Artist" });

        try
        {
            var owned = await GetAsync<PagedResult<AlbumDto>>($"/{ResourceEndpoint}?IsOwned=true&search={title}");
            owned.Items.Should().ContainSingle(x => x.Id == created.Id);
            owned.Items.Should().NotContain(x => x.Id == notOwned.Id);

            // the version's fields must survive the full DTO -> model -> BSON round trip (incl. the decimal price)
            owned.Items.Single(x => x.Id == created.Id).OwnedVersions.Should().BeEquivalentTo(created.OwnedVersions);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{notOwned.Id}");
        }
    }

    [Fact]
    public async Task AlbumResourceSearch_FiltersToMatchingTitleOrArtist_IsOk()
    {
        await Authenticate();

        var title = System.Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", new AlbumDto { Title = title, Artist = "Search Test Artist" });

        try
        {
            var results = await GetAsync<PagedResult<AlbumDto>>($"/{ResourceEndpoint}?search={title}");

            results.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
