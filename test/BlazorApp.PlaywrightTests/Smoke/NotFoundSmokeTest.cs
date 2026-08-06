using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// The 404 wiring, which nothing below the browser can prove: an unknown URL has to come back with a real 404
/// status *and* the rendered page, which takes the status-code middleware re-executing onto <c>/not-found</c>
/// (Program.cs) and the page rendering statically so it can read the original status (NotFound.razor).
/// Read-only safe - a missing page creates nothing - so this runs under <c>E2E_READONLY</c> too.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Readonly")]
public class NotFoundSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task UnknownUrl_RendersTheNotFoundPage_WithARealNotFoundStatus()
    {
        var response = await Page.GotoAsync("/no-such-page-e2e");

        Assert.NotNull(response);
        Assert.Equal(404, response.Status);
        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Page not found" }))
            .ToBeVisibleAsync();
        // the generic error page is the outcome this whole mechanism exists to replace
        await Assertions.Expect(Page.Locator("#blazor-error-ui")).ToBeHiddenAsync();
    }

    /// <summary>
    /// A signed-out visitor following a dead link must land here rather than on login: bouncing them would say
    /// the page exists. The shared context is signed in, so this needs its own clean one (same reasoning as
    /// <see cref="AuthSmokeTest"/>).
    /// </summary>
    [Fact]
    public async Task UnknownUrl_ShowsTheNotFoundPage_ToAnAnonymousVisitor()
    {
        var anonymousPage = await NewAnonymousPageAsync();

        var response = await anonymousPage.GotoAsync("/no-such-page-e2e");

        Assert.NotNull(response);
        Assert.Equal(404, response.Status);
        await Assertions.Expect(anonymousPage.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Page not found" }))
            .ToBeVisibleAsync();
    }
}
