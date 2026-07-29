using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Regression guard for the "'RemoteNavigationManager' has not been initialized" red error: a signed-in
/// session whose Firebase ID token has gone stale (the 8h auth cookie still valid, but the ~1h token expired
/// or revoked) must be cleanly redirected to login when a server-rendered page's API call comes back 401 -
/// not crash the render and force a manual page refresh. Before the fix, <c>AuthenticationTokenHandler</c>
/// resolved its <c>NavigationManager</c> from the wrong DI scope (the IHttpClientFactory handler scope, whose
/// RemoteNavigationManager the renderer never initialized), so reading its <c>.Uri</c> during the SSR/prerender
/// pass threw instead of redirecting.
/// </summary>
[Trait("Category", "E2eTests")]
[Trait("Mode", "Readonly")]
public class StaleTokenRedirectSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task StaleFirebaseToken_On401_RedirectsToLogin_InsteadOfCrashingTheServerRender()
    {
        var cookie = Fixture.ForgeStaleTokenMemberCookie();
        Assert.SkipWhen(cookie is null, "Forging a stale-token cookie needs the in-process Blazor host (self-hosted integration mode only).");

        // A fresh context with none of the run's signed-in storage state - this test supplies its own forged cookie
        // (a valid member principal carrying a Firebase token WebApi will reject), same clean-context approach as AuthSmokeTest.
        await using var context = await NewContext(new BrowserNewContextOptions
        {
            BaseURL = Fixture.BlazorBaseUrl,
            IgnoreHTTPSErrors = true
        });
        await context.AddCookiesAsync([cookie!]);
        var page = await context.NewPageAsync();

        // The shared-collection page (the one in the original report) loads via OnInitializedAsync with no
        // try/catch, so the 401 propagates straight into the redirect path under test - unlike the inventory
        // list pages, which swallow it into an inline error message. The ShareId need not exist: the API call is
        // rejected on the stale bearer token before any lookup runs.
        await page.GotoAsync($"/account/manage/shared/{Guid.NewGuid():N}");

        await new LoginPage(page).WaitForReadyAsync();
    }
}
