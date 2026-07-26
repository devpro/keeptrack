using System;
using System.Collections.Generic;
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
    public async Task GearResourceCategoryFilter_OnlyReturnsMatchingItems_IsOk()
    {
        await Authenticate();

        var title = $"CategoryTarget-{System.Guid.NewGuid():N}";
        var electronics = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title, Category = "Electronics" });
        var camping = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title, Category = "Camping" });
        var uncategorized = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title });

        try
        {
            var results = await GetAsync<PagedResult<GearDto>>($"/{ResourceEndpoint}?Category=Electronics&search={title}");
            results.Items.Should().ContainSingle(x => x.Id == electronics.Id);
            results.Items.Should().NotContain(x => x.Id == camping.Id || x.Id == uncategorized.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{electronics.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{camping.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{uncategorized.Id}");
        }
    }

    [Fact]
    public async Task GearCategoriesEndpoint_ReturnsDistinctSortedCategories_IsOk()
    {
        await Authenticate();

        var title = $"CategoryList-{System.Guid.NewGuid():N}";
        var first = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title, Category = "Zetatools" });
        var second = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title, Category = "Anvils" });
        // same category twice must appear only once, and an unset category must never appear at all
        var duplicate = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title, Category = "Zetatools" });
        var uncategorized = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title });

        try
        {
            var categories = await GetAsync<List<string>>($"/{ResourceEndpoint}/categories");
            categories.Should().Contain(["Anvils", "Zetatools"]);
            categories.Should().OnlyHaveUniqueItems();
            var anvilsIndex = categories.IndexOf("Anvils");
            var zetatoolsIndex = categories.IndexOf("Zetatools");
            anvilsIndex.Should().BeLessThan(zetatoolsIndex, "results are sorted alphabetically");
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{first.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{second.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{duplicate.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{uncategorized.Id}");
        }
    }

    [Fact]
    public async Task GearResourceBoughtSort_OrdersByMostRecentlyAcquiredCopyDescending_IsOk()
    {
        await Authenticate();

        var title = $"BoughtSort-{System.Guid.NewGuid():N}";
        var olderPurchase = await PostAsync($"/{ResourceEndpoint}", new GearDto
        {
            Title = title,
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Physical, AcquiredAt = new DateOnly(2020, 1, 1) }]
        });
        var recentPurchase = await PostAsync($"/{ResourceEndpoint}", new GearDto
        {
            Title = title,
            OwnedVersions = [new OwnedVersionDto { CopyType = CopyType.Physical, AcquiredAt = new DateOnly(2024, 6, 1) }]
        });
        var neverOwned = await PostAsync($"/{ResourceEndpoint}", new GearDto { Title = title });

        try
        {
            var results = await GetAsync<PagedResult<GearDto>>($"/{ResourceEndpoint}?sort=bought&search={title}");
            var ids = results.Items.Select(x => x.Id).ToList();
            ids.IndexOf(recentPurchase.Id).Should().BeLessThan(ids.IndexOf(olderPurchase.Id),
                "the most recently acquired copy sorts first");
            ids.Should().Contain(neverOwned.Id, "an unset acquisition date still falls back to the newest-first tie-break, it isn't excluded");
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{olderPurchase.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{recentPurchase.Id}");
            await DeleteAsync($"/{ResourceEndpoint}/{neverOwned.Id}");
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
