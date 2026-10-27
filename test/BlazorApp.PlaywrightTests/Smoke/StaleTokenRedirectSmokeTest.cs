using System;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// A session whose Firebase ID token went stale (the 8h cookie valid, the 1h token expired or revoked) is redirected to login when a server-rendered page's API call answers 401.
/// It must not throw "'RemoteNavigationManager' has not been initialized" and force a manual refresh.
/// <c>AuthenticationTokenHandler</c> resolves its <c>NavigationManager</c> from the request scope,
/// since the IHttpClientFactory handler scope's is never initialized during prerender.
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

        // A fresh context without the run's signed-in storage state,
        // since this test supplies its own forged cookie (a valid member principal with a token WebApi rejects), like AuthSmokeTest.
        var page = await NewAnonymousPageAsync("stale-token");
        await page.Context.AddCookiesAsync([cookie!]);

        // The shared-collection page loads in OnInitializedAsync with no try/catch,
        // so the 401 reaches the redirect path under test, unlike the inventory list pages, which show an inline error.
        // The ShareId need not exist: the API call is rejected on the stale bearer token before any lookup runs.
        await page.GotoAsync($"/account/manage/shared/{Guid.NewGuid():N}");

        await new LoginPage(page).WaitForReadyAsync();
    }
}
