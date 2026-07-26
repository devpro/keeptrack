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
/// Basic full-cycle CRUD coverage for <c>Collectible</c>, same shape as <see cref="AlbumResourceTest"/>
/// minus reference-linking (Collectible has no external reference-data provider).
/// </summary>
public class CollectibleResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/collectibles";

    [Fact]
    public async Task CollectibleResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var input = new Faker<CollectibleDto>()
            .Rules((f, o) =>
            {
                o.Title = f.Random.AlphaNumeric(14);
                o.Brand = f.Company.CompanyName();
                o.Year = f.Random.Int(1990, 2024);
                o.Notes = f.Lorem.Sentence();
                o.ImageUrl = f.Internet.Url();
            })
            .Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Title = "New shiny title";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<CollectibleDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<CollectibleDto>>($"/{ResourceEndpoint}");
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
    public async Task CollectibleResourceSearch_FiltersByTitle_IsOk()
    {
        await Authenticate();

        var title = System.Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", new CollectibleDto { Title = title });

        try
        {
            var results = await GetAsync<PagedResult<CollectibleDto>>($"/{ResourceEndpoint}?search={title}");
            results.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task CollectibleResourceOwnedAndFavoriteFilters_OnlyReturnMatchingItems_IsOk()
    {
        await Authenticate();

        var title = $"OwnedTarget-{System.Guid.NewGuid():N}";
        var owned = await PostAsync($"/{ResourceEndpoint}", new CollectibleDto
        {
            Title = title,
            // "owned" is derived from having at least one owned version, not a stored flag
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Physical, Price = 42.50m, ProductName = "Ultimate Collector's Edition" }]
        });
        var favorite = await PostAsync($"/{ResourceEndpoint}", new CollectibleDto { Title = title, IsFavorite = true });
        var plain = await PostAsync($"/{ResourceEndpoint}", new CollectibleDto { Title = title });

        try
        {
            var ownedResults = await GetAsync<PagedResult<CollectibleDto>>($"/{ResourceEndpoint}?IsOwned=true&search={title}");
            ownedResults.Items.Should().ContainSingle(x => x.Id == owned.Id);
            ownedResults.Items.Should().NotContain(x => x.Id == plain.Id);
            // the version's fields must survive the full DTO -> model -> BSON round trip, including ProductName
            ownedResults.Items.Single(x => x.Id == owned.Id).OwnedVersions.Should().BeEquivalentTo(owned.OwnedVersions);

            var favoriteResults = await GetAsync<PagedResult<CollectibleDto>>($"/{ResourceEndpoint}?IsFavorite=true&search={title}");
            favoriteResults.Items.Should().ContainSingle(x => x.Id == favorite.Id);
            favoriteResults.Items.Should().NotContain(x => x.Id == plain.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{owned.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{favorite.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{plain.Id}");
        }
    }
}
