using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using KeepTrack.WebApi.Dto;
using KeepTrack.WebApi.IntegrationTests.TestingLogic.Resources;
using Xunit;
using Xunit.Sdk;

namespace KeepTrack.WebApi.IntegrationTests.Production;

[Trait("Environment", "Production")]
public class MovieResourceProductionTest()
    : ResourceBase(Environment.GetEnvironmentVariable("Keeptrack__Production__Url") ?? throw new InvalidOperationException())
{
    private const string ResourceEndpoint = "api/movies";

    [Fact]
    public async Task MovieResourceProductionFullCycle_IsOk()
    {
        // check not authorized if not logged
        (await Assert.ThrowsAsync<XunitException>(async () => await GetAsync<List<MovieDto>>($"/{ResourceEndpoint}")))
            .Message.Should().Be("Expected the enum to be HttpStatusCode.OK {value: 200}, but found HttpStatusCode.Unauthorized {value: 401}.");

        await Authenticate();

        var input = Fixture.Create<MovieDto>();
        input.Id = null;
        var created = await PostAsync<MovieDto>($"/{ResourceEndpoint}", input.ToJson());

        try
        {
            created.Title = "New shiny title";
            await PutAsync<MovieDto>($"/{ResourceEndpoint}/{created.Id}", created.ToJson());

            var updated = await GetAsync<MovieDto>($"/{ResourceEndpoint}/{created.Id}");
            updated.Should().BeEquivalentTo(created);

            var finalItems = await GetAsync<List<MovieDto>>($"/{ResourceEndpoint}");
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
