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
/// Basic full-cycle CRUD coverage for <c>Gear</c>, same shape as <see cref="CollectibleResourceTest"/>
/// (Gear has no external reference-data provider either).
/// </summary>
public class GearResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/gear";

    [Fact]
    public async Task GearResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var input = new Faker<GearDto>()
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

            var updated = await GetAsync<GearDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<GearDto>>($"/{ResourceEndpoint}");
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
    public async Task GearResourceSearch_FiltersByTitle_IsOk()
    {
        await Authenticate();

        var title = System.Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title });

        try
        {
            var results = await GetAsync<PagedResult<GearDto>>($"/{ResourceEndpoint}?search={title}");
            results.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task GearResourceOwnedAndFavoriteFilters_OnlyReturnMatchingItems_IsOk()
    {
        await Authenticate();

        var title = $"OwnedTarget-{System.Guid.NewGuid():N}";
        var owned = await PostAsync($"/{ResourceEndpoint}", new GearDto
        {
            Title = title,
            // "owned" is derived from having at least one owned version, not a stored flag
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Physical, Price = 199.99m, ProductName = "Limited edition" }]
        });
        var favorite = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title, IsFavorite = true });
        var plain = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title });

        try
        {
            var ownedResults = await GetAsync<PagedResult<GearDto>>($"/{ResourceEndpoint}?IsOwned=true&search={title}");
            ownedResults.Items.Should().ContainSingle(x => x.Id == owned.Id);
            ownedResults.Items.Should().NotContain(x => x.Id == plain.Id);
            // the version's fields must survive the full DTO -> model -> BSON round trip, including ProductName
            ownedResults.Items.Single(x => x.Id == owned.Id).OwnedVersions.Should().BeEquivalentTo(owned.OwnedVersions);

            var favoriteResults = await GetAsync<PagedResult<GearDto>>($"/{ResourceEndpoint}?IsFavorite=true&search={title}");
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
