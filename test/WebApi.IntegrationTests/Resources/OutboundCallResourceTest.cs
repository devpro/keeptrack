using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Testing.Shared.Providers;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// A run without live providers sends nothing out of the machine, whatever keys its host found.
/// The address is reserved and resolves nowhere, so an answer can only come from the refusal.
/// </summary>
public class OutboundCallResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Theory]
    [InlineData("")]
    [InlineData(IgdbTokenProvider.TokenHttpClientName)]
    [InlineData(nameof(ITmdbClient))]
    [InlineData(nameof(BnfClient))]
    public async Task AnOutboundCall_IsRefused_WithoutLiveProviders(string clientName)
    {
        Assert.SkipWhen(LiveProviders.Enabled, "TEST_LIVE_PROVIDERS is true, so the calls go out.");
        using var client = Factory.Services.GetRequiredService<IHttpClientFactory>().CreateClient(clientName);

        using var response = await client.GetAsync(new Uri("https://provider.invalid/"), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }
}
