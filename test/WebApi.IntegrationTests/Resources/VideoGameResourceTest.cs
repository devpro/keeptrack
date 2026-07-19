using System;
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
/// Basic full-cycle CRUD coverage for <c>VideoGame</c> - closes a gap flagged in
/// docs/code-quality-findings.md ("...VideoGame still have none"), same shape as <see cref="BookResourceTest"/>.
/// </summary>
public class VideoGameResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/video-games";

    [Fact]
    public async Task VideoGameResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var input = new Faker<VideoGameDto>()
            .Rules((f, o) =>
            {
                o.Title = f.Random.AlphaNumeric(14);
                o.Platforms = [new VideoGamePlatformDto { Platform = "PC", CopyType = CopyType.Physical, State = "Current" }];
            })
            .Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Title = "New shiny title";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<VideoGameDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<VideoGameDto>>($"/{ResourceEndpoint}");
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
    public async Task VideoGameResourceSearch_FiltersToMatchingPlatform_IsOk()
    {
        await Authenticate();

        var title = System.Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", new VideoGameDto
        {
            Title = title,
            Platforms = [new VideoGamePlatformDto { Platform = "PS5", CopyType = CopyType.Physical, State = "Available" }]
        });

        try
        {
            var results = await GetAsync<PagedResult<VideoGameDto>>($"/{ResourceEndpoint}?platform=PS5&search={title}");

            results.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task VideoGameResourceOwnedAndWishlistedFilters_OnlyReturnMatchingItems_IsOk()
    {
        await Authenticate();

        var title = Guid.NewGuid().ToString();
        var platforms = new[]
        {
            // "owned" is derived from having at least one platform entry (a game's copies), not a stored flag -
            // this entry also carries the same ownership fields (price/vendor/acquired/reference) as every
            // other media type's owned copies, see OwnedVersionModel
            new VideoGamePlatformDto
            {
                Platform = "PS5", CopyType = CopyType.Physical, State = "Available",
                Price = 59.99m, Vendor = "Some store", Reference = "Collector's edition", AcquiredAt = new DateOnly(2024, 5, 17)
            }
        };
        var created = await PostAsync($"/{ResourceEndpoint}", new VideoGameDto
        {
            Title = title,
            Platforms = [.. platforms],
            IsWishlisted = true
        });

        try
        {
            var owned = await GetAsync<PagedResult<VideoGameDto>>($"/{ResourceEndpoint}?IsOwned=true&search={title}");
            owned.Items.Should().ContainSingle(x => x.Id == created.Id);

            // the platform entry's ownership fields must survive the full DTO -> model -> BSON round trip (incl. the decimal price)
            var fetchedPlatforms = owned.Items.Single(x => x.Id == created.Id).Platforms;
            fetchedPlatforms.Should().BeEquivalentTo(platforms);

            // this is the WishlistController filter-probe, not a list-page UI filter (removed) - still real API behavior
            var wishlisted = await GetAsync<PagedResult<VideoGameDto>>($"/{ResourceEndpoint}?IsWishlisted=true&search={title}");
            wishlisted.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
