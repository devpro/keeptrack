using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
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

    /// <summary>
    /// The other two tests above both reach <c>/not-found</c> through <c>Page.GotoAsync</c>, a full browser navigation that only ever exercises <c>UseStatusCodePagesWithReExecute</c>.
    /// AGENTS.md documents a second, genuinely different path: once a page is interactively routed (<c>App.razor</c>'s <c>RenderModeForPage</c> gives every page but this one <c>InteractiveServer</c>), an in-circuit navigation to an unknown route is resolved by the Blazor Web App router over the already-open circuit rather than by the server's status-code middleware.
    /// That is the same code path a <c>NavLink</c> click to a stale route would take.
    /// <c>Blazor.navigateTo</c> is the documented JS API a <c>NavLink</c> click resolves to internally, so it's the direct way to trigger that path from Playwright without a DOM hack.
    /// <para>
    /// Two things confirmed only by actually running this test, not by reasoning about it: <c>Page.FrameNavigated</c> is not a valid "no full page load" signal, since it fires for a plain <c>history.pushState</c> URL change too, and it fired here even on a genuine in-circuit navigation.
    /// And "in-circuit" does not mean zero network traffic: enhanced navigation still issues a background <c>fetch</c> for the new route (a <c>ResourceType</c> of <c>fetch</c>, confirmed via <c>Page.Request</c>) to retrieve the content it patches into the existing document.
    /// The one signal that actually distinguishes the two paths is <see cref="IRequest.IsNavigationRequest"/>: true for the real document load <c>Page.GotoAsync</c> causes above, false for enhanced navigation's own fetch.
    /// </para>
    /// </summary>
    [Fact]
    public async Task InCircuitNavigation_ToAnUnknownRoute_RendersTheNotFoundPage_WithNoFullDocumentNavigation()
    {
        await new HomePage(Page).OpenAsync();

        var navigationRequestsToTarget = new List<string>();
        Page.Request += (_, request) =>
        {
            if (request.Url.Contains("no-such-page-e2e-in-circuit") && request.IsNavigationRequest)
                navigationRequestsToTarget.Add(request.Url);
        };

        await Page.EvaluateAsync("Blazor.navigateTo('/no-such-page-e2e-in-circuit', false)");

        await Assertions.Expect(Page.GetByRole(AriaRole.Heading, new PageGetByRoleOptions { Name = "Page not found" }))
            .ToBeVisibleAsync();
        Page.Url.Should().EndWith("/no-such-page-e2e-in-circuit");
        navigationRequestsToTarget.Should().BeEmpty(
            "an in-circuit route change is resolved by the router over the existing document, never by a fresh top-level navigation to the new path");
    }
}
