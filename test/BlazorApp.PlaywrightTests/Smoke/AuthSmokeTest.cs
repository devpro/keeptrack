using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

[Trait("Category", "E2eTests")]
[Trait("Mode", "Readonly")]
public class AuthSmokeTest(End2EndFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AnonymousVisit_ToProtectedPage_RedirectsToLogin()
    {
        // The shared Page/Context (from SmokeTestBase.ContextOptions) already carries a signed-in storage state -
        // a genuinely anonymous visit needs its own context with none, per the e2e plan ("only the dedicated auth test uses a clean context").
        var anonymousPage = await NewAnonymousPageAsync();

        await anonymousPage.GotoAsync("/books");

        await new LoginPage(anonymousPage).WaitForReadyAsync();
    }

    [Fact]
    public async Task Logout_EndsTheSession()
    {
        var home = await new HomePage(Page).OpenAsync();
        await home.LogoutAsync();

        await Page.GotoAsync("/books");

        await new LoginPage(Page).WaitForReadyAsync();
    }

    /// <summary>
    /// <c>AuthenticationController.Callback</c> itself has no test below the browser: every other test here
    /// reaches it only through the fixture's own sign-in setup with a genuinely valid token.
    /// These three exercise its own validation, over a direct POST rather than a page navigation.
    /// </summary>
    [Fact]
    public async Task Callback_WithNoToken_Answers400()
    {
        var response = await Context.APIRequest.PostAsync("/auth/callback",
            new APIRequestContextOptions { DataObject = new { idToken = "" } });

        Assert.Equal(400, response.Status);
    }

    [Fact]
    public async Task Callback_WithAnInvalidToken_Answers401()
    {
        var response = await Context.APIRequest.PostAsync("/auth/callback",
            new APIRequestContextOptions { DataObject = new { idToken = "not-a-real-firebase-token" } });

        Assert.Equal(401, response.Status);
    }

    /// <summary>
    /// The shared context's storage state is a signed-in session, so this needs its own anonymous one to
    /// prove the "must already be signed in" check, same reasoning as the anonymous-visit test above.
    /// </summary>
    [Fact]
    public async Task Refresh_WhenNotSignedIn_Answers401()
    {
        var anonymousPage = await NewAnonymousPageAsync("refresh-unauthenticated");

        var response = await anonymousPage.Context.APIRequest.PostAsync("/auth/refresh",
            new APIRequestContextOptions { DataObject = new { idToken = "irrelevant" } });

        Assert.Equal(401, response.Status);
    }

    /// <summary>
    /// The core guard in <c>AuthenticationController.Refresh</c>: a token that verifies fine but belongs to
    /// a different Firebase user must never be allowed to swap the identity behind an existing session.
    /// </summary>
    [Fact]
    public async Task Refresh_WithAnotherUsersValidToken_Answers401()
    {
        var anotherUsersToken = await Fixture.GetAnotherUsersIdTokenAsync();
        Assert.SkipWhen(anotherUsersToken is null,
            "Minting a second identity needs the in-process Blazor host's own Firebase Admin SDK access (self-hosted integration mode only).");

        // The shared context is already signed in as the run's own identity.
        var response = await Context.APIRequest.PostAsync("/auth/refresh",
            new APIRequestContextOptions { DataObject = new { idToken = anotherUsersToken } });

        Assert.Equal(401, response.Status);
    }
}
