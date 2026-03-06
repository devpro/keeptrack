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

public class BookResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/books";

    [Fact]
    public async Task BookResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var initialItems = await GetAsync<List<BookDto>>($"/{ResourceEndpoint}");

        var input = new Faker<BookDto>()
            .Rules((f, o) => { o.Author = f.Random.AlphaNumeric(8); o.Title = f.Random.AlphaNumeric(14); })
            .Generate();
        var created = await PostAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Title = "New shiny title";
            await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

            var updated = await GetAsync<BookDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created, x => x.Excluding(item => item.FinishedAt)); // issue with DateTime and MongoDB

            var finalItems = await GetAsync<List<BookDto>>($"/{ResourceEndpoint}");
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
