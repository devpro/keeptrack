using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using KeepTrack.WebApi.Dto;
using KeepTrack.WebApi.IntegrationTests.TestingLogic.Resources;
using Xunit;
using Xunit.Sdk;

namespace KeepTrack.WebApi.IntegrationTests.Production;

[Trait("Environment", "Production")]
public class BookResourceProductionTest()
    : ResourceBase(Environment.GetEnvironmentVariable("Keeptrack__Production__Url") ?? throw new InvalidOperationException())
{
    private const string ResourceEndpoint = "api/books";

    [Fact]
    public async Task BookResourceProductionFullCycle_IsOk()
    {
        // check not authorized if not logged
        (await Assert.ThrowsAsync<XunitException>(async () => await GetAsync<List<BookDto>>($"/{ResourceEndpoint}")))
            .Message.Should().Be("Expected the enum to be HttpStatusCode.OK {value: 200}, but found HttpStatusCode.Unauthorized {value: 401}.");

        await Authenticate();

        var input = Fixture.Create<BookDto>();
        input.Id = null;
        var created = await PostAsync<BookDto>($"/{ResourceEndpoint}", JsonSerializer.Serialize(input));

        try
        {
            created.Title = "New shiny title";
            await PutAsync<BookDto>($"/{ResourceEndpoint}/{created.Id}", JsonSerializer.Serialize(input));

            var updated = await GetAsync<BookDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created, x => x.Excluding(item => item.FinishedAt)); // issue with DateTime and MongoDB

            var finalItems = await GetAsync<List<BookDto>>($"/{ResourceEndpoint}");
            finalItems.Count.Should().BeGreaterThanOrEqualTo(1);
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
