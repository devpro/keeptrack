using System.Collections.Generic;
using System.Threading.Tasks;
using KeepTrack.WebApi.Dto;
using KeepTrack.WebApi.IntegrationTests.TestingLogic.Resources;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using Xunit.Sdk;

namespace KeepTrack.WebApi.IntegrationTests.Localhost;

[Trait("Environment", "Localhost")]
public class BookResourceLocalhostTest(WebApplicationFactory<Program> factory)
    : ResourceBase(factory.CreateClient()), IClassFixture<WebApplicationFactory<Program>>
{
    private const string ResourceEndpoint = "api/books";

    [Fact]
    public async Task BookResourceLocalhostFullCycle_IsOk()
    {
        // check not authorized if not logged
        (await Assert.ThrowsAsync<XunitException>(async () => await GetAsync<List<BookDto>>($"/{ResourceEndpoint}")))
            .Message.Should().Be("Expected the enum to be HttpStatusCode.OK {value: 200}, but found HttpStatusCode.Unauthorized {value: 401}.");

        await Authenticate();

        var initialItems = await GetAsync<List<BookDto>>($"/{ResourceEndpoint}");
        initialItems.Count.Should().Be(0);

        var input = Fixture.Create<BookDto>();
        input.Id = null;
        var created = await PostAsync<BookDto>($"/{ResourceEndpoint}", input.ToJson());
        created.Id.Should().NotBeNullOrEmpty();

        try
        {
            created.Title = "New shiny title";
            await PutAsync<BookDto>($"/{ResourceEndpoint}/{created.Id}", created.ToJson());

            var updated = await GetAsync<BookDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created, x => x.Excluding(item => item.FinishedAt)); // issue with DateTime and MongoDB

            var finalItems = await GetAsync<List<BookDto>>($"/{ResourceEndpoint}");
            finalItems.Count.Should().Be(1);
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
