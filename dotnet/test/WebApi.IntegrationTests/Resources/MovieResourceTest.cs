using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Bogus;
using KeepTrack.WebApi.Dto;
using KeepTrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace KeepTrack.WebApi.IntegrationTests.Resources;

public class MovieResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/movies";

    [Fact]
    public async Task MovieResourceLocalhostFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var initialItems = await GetAsync<List<MovieDto>>($"/{ResourceEndpoint}");

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

            var finalItems = await GetAsync<List<MovieDto>>($"/{ResourceEndpoint}");
            finalItems.Count.Should().BeGreaterThan(initialItems.Count);
            finalItems[0].Id.Should().Be(updated.Id);
            var firstItem = finalItems.FirstOrDefault(x => x.Id == updated.Id);
            firstItem.Should().NotBeNull();
            firstItem.Title.Should().Be(updated.Title);
        }
        finally
        {
            await DeleteAsync($"/{ResourceEndpoint}/{created.Id}");
        }
    }
}
