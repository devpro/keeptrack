using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Bogus;
using KeepTrack.Common.Collections.Generic;
using KeepTrack.WebApi.Contracts.Dto;
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

        var initialItems = await GetAsync<PagedResult<BookDto>>($"/{ResourceEndpoint}");

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

            var finalItems = await GetAsync<PagedResult<BookDto>>($"/{ResourceEndpoint}");
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
