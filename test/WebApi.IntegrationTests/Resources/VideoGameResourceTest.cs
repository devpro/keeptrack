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

        var initialItems = await GetAsync<PagedResult<VideoGameDto>>($"/{ResourceEndpoint}");

        var input = new Faker<VideoGameDto>()
            .Rules((f, o) =>
            {
                o.Title = f.Random.AlphaNumeric(14);
                o.Platforms = [new VideoGamePlatformDto { Platform = "PC", CopyType = VideoGameCopyType.Physical, State = "Current" }];
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
    public async Task VideoGameResourceSearch_FiltersToMatchingPlatform_IsOk()
    {
        await Authenticate();

        var title = System.Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", new VideoGameDto
        {
            Title = title,
            Platforms = [new VideoGamePlatformDto { Platform = "PS5", CopyType = VideoGameCopyType.Physical, State = "Available" }]
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

        var title = System.Guid.NewGuid().ToString();
        var created = await PostAsync($"/{ResourceEndpoint}", new VideoGameDto
        {
            Title = title,
            Platforms = [new VideoGamePlatformDto { Platform = "PS5", CopyType = VideoGameCopyType.Physical, State = "Available" }],
            IsOwned = true,
            IsWishlisted = true
        });

        try
        {
            var owned = await GetAsync<PagedResult<VideoGameDto>>($"/{ResourceEndpoint}?IsOwned=true&search={title}");
            owned.Items.Should().ContainSingle(x => x.Id == created.Id);

            var wishlisted = await GetAsync<PagedResult<VideoGameDto>>($"/{ResourceEndpoint}?IsWishlisted=true&search={title}");
            wishlisted.Items.Should().ContainSingle(x => x.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
