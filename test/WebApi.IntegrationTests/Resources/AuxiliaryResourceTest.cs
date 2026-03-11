using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

[Trait("Category", "IntegrationTests")]
public class AuxiliaryResourceTest(WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    [Trait("Mode", "Readonly")]
    [Theory]
    [InlineData("/health", HttpStatusCode.OK, "text/plain", "Healthy")]
    [InlineData("/scalar", HttpStatusCode.OK, "text/html", "<title>Keeptrack Web API</title>")]
    [InlineData("/openapi/v1.json", HttpStatusCode.OK, "application/json; charset=utf-8", "\"title\": \"Keeptrack Web API\"")]
    public async Task AuxiliaryResource_Get_ReturnsExpectedResponse(string url,
        HttpStatusCode expectedStatus,
        string expectedContentType,
        string expectedContent)
    {
        var client = factory.CreateClient();

        var response = await client.GetAsync(url, TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(expectedStatus);

        response.Content.Headers.ContentType?.ToString().Should().Be(expectedContentType);

        var result = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        result.Should().Contain(expectedContent);
    }
}
