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

public class MovieResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/movies";

    [Fact]
    public async Task MovieResourceLocalhostFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var initialItems = await GetAsync<PagedResult<MovieDto>>($"/{ResourceEndpoint}");

        var input = new Faker<MovieDto>()
            .Rules((f, o) => { o.Title = f.Random.AlphaNumeric(14); })
            .Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Title = "New shiny title";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<MovieDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<PagedResult<MovieDto>>($"/{ResourceEndpoint}");
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
    public async Task MovieResourceSearch_FiltersToMatchingTitle_IsOk()
    {
        await Authenticate();

        var uniqueTitle = $"UniqueSearchTarget-{Guid.NewGuid():N}";
        var input = new Faker<MovieDto>().Rules((f, o) => { o.Title = uniqueTitle; }).Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);

        try
        {
            var matching = await GetAsync<PagedResult<MovieDto>>($"/{ResourceEndpoint}?search={uniqueTitle}");
            matching.Items.Should().Contain(m => m.Id == created.Id);

            var nonMatching = await GetAsync<PagedResult<MovieDto>>($"/{ResourceEndpoint}?search={Guid.NewGuid():N}");
            nonMatching.Items.Should().NotContain(m => m.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }

    [Fact]
    public async Task MovieResourceOwnedAndWishlistedFilters_OnlyReturnMatchingItems_IsOk()
    {
        await Authenticate();

        var uniqueTitle = $"OwnedWishlistTarget-{Guid.NewGuid():N}";
        var input = new Faker<MovieDto>()
            .Rules((f, o) =>
            {
                o.Title = uniqueTitle;
                o.IsOwned = true;
                o.IsWishlisted = true;
            })
            .Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);

        try
        {
            var owned = await GetAsync<PagedResult<MovieDto>>($"/{ResourceEndpoint}?IsOwned=true&search={uniqueTitle}");
            owned.Items.Should().ContainSingle(m => m.Id == created.Id);

            var wishlisted = await GetAsync<PagedResult<MovieDto>>($"/{ResourceEndpoint}?IsWishlisted=true&search={uniqueTitle}");
            wishlisted.Items.Should().ContainSingle(m => m.Id == created.Id);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
