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
}
