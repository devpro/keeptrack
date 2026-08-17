using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Bogus;
using Keeptrack.Common.System;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Basic full-cycle CRUD coverage for the renamed <c>Album</c> type (formerly <c>MusicAlbum</c>) - closes
/// a gap flagged in docs/findings/by-design-and-gaps.md ("MusicAlbum...still has none"), same shape as
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
            .Rules((f, o) =>
            {
                o.Artist = f.Random.AlphaNumeric(8);
                o.Title = f.Random.AlphaNumeric(14);
                // round-trips CustomImageUrl through the real Mapperly mappers + MongoDB - a plain scalar field
                // with no special mapping, but a real integration test is what would catch a missed
                // [BsonElement]/mapper ignore, not a mocked unit test.
                o.CustomImageUrl = f.Internet.Url();
            })
            .Generate();
        var created = await CreateAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        created.Title = "New shiny title";
        await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

        var updated = await GetAsync<AlbumDto>($"/{ResourceEndpoint}/{created.Id}");
        updated.Should().BeEquivalentTo(created);

        var finalItems = await GetAsync<PagedResult<AlbumDto>>($"/{ResourceEndpoint}");
        var firstItem = finalItems.Items.FirstOrDefault(x => x.Id == updated.Id);
        firstItem.Should().NotBeNull();
        firstItem.Title.Should().Be(updated.Title);
    }

    [Fact]
    public async Task AlbumResourceUpdate_PersistsArtistChange_IsOk()
    {
        // regression test for a reported "editing the artist doesn't update the data" bug - full review of
        // AlbumDetail.razor/Albums.razor/AlbumApiClient/DataCrudControllerBase/both mapper layers found
        // no code-level cause (identical shape to Book's Author editing, which isn't reported as broken); this
        // locks in that a PUT changing only Artist persists correctly end-to-end.
        await Authenticate();

        var created = await CreateAsync($"/{ResourceEndpoint}", new AlbumDto { Title = "Artist Update Test", Artist = "Original Artist" });

        created.Artist = "Updated Artist";
        await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

        var updated = await GetAsync<AlbumDto>($"/{ResourceEndpoint}/{created.Id}");
        updated.Artist.Should().Be("Updated Artist");
    }

    [Fact]
    public async Task AlbumResourceOwnedFilter_OnlyReturnsAlbumsWithOwnedVersions_IsOk()
    {
        await Authenticate();

        var title = $"OwnedTarget-{Guid.NewGuid():N}";
        var created = await CreateAsync($"/{ResourceEndpoint}", new AlbumDto
        {
            Title = title,
            Artist = "Owned Filter Artist",
            // "owned" is derived from having at least one owned version, not a stored flag
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Physical, Price = 24.50m, Vendor = "Record store", Reference = "Vinyl reissue", ProductName = "Deluxe vinyl edition" }]
        });
        var notOwned = await CreateAsync($"/{ResourceEndpoint}", new AlbumDto { Title = title, Artist = "Owned Filter Artist" });

        var owned = await GetAsync<PagedResult<AlbumDto>>($"/{ResourceEndpoint}?IsOwned=true&search={title}");
        owned.Items.Should().ContainSingle(x => x.Id == created.Id);
        owned.Items.Should().NotContain(x => x.Id == notOwned.Id);

        // the version's fields must survive the full DTO -> model -> BSON round trip (incl. the decimal price)
        owned.Items.Single(x => x.Id == created.Id).OwnedVersions.Should().BeEquivalentTo(created.OwnedVersions);
    }

    [Fact]
    public async Task AlbumResourceSearch_FiltersToMatchingTitleOrArtist_IsOk()
    {
        await Authenticate();

        var title = Guid.NewGuid().ToString();
        var created = await CreateAsync($"/{ResourceEndpoint}", new AlbumDto { Title = title, Artist = "Search Test Artist" });

        var results = await GetAsync<PagedResult<AlbumDto>>($"/{ResourceEndpoint}?search={title}");

        results.Items.Should().ContainSingle(x => x.Id == created.Id);
    }

    /// <summary>
    /// <see cref="AlbumDto.CustomImageUrl"/> follows <see cref="BookDto.CustomImageUrl"/>'s exact
    /// shape - <c>AlbumController.OnListMappedAsync</c> is expected to apply it over the linked reference's own
    /// cover on every list read.
    /// </summary>
    [Fact]
    public async Task AlbumResourceList_CustomImageUrlOverridesTheLinkedReferencesCover()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var uniqueTitle = $"CustomImageOverrideTarget-{Guid.NewGuid():N}";

        var reference = await referenceRepository.UpsertAsync(new Keeptrack.Domain.Models.AlbumReferenceModel
        {
            Title = "Some Reference Title",
            TitleNormalized = "some reference title",
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() },
            ImageUrl = "https://example.com/reference-cover.jpg"
        });
        TrackDocument("album_reference", reference.Id);

        await Authenticate();
        const string customImageUrl = "https://example.com/custom-cover.jpg";
        var created = await CreateAsync($"/{ResourceEndpoint}", new AlbumDto
        {
            Title = uniqueTitle,
            Artist = "Some Artist",
            ReferenceId = reference.Id,
            CustomImageUrl = customImageUrl
        });

        var list = await GetAsync<PagedResult<AlbumDto>>($"/{ResourceEndpoint}?search={uniqueTitle}");
        var item = list.Items.Should().ContainSingle(x => x.Id == created.Id).Subject;
        item.ImageUrl.Should().Be(customImageUrl);
    }
}
