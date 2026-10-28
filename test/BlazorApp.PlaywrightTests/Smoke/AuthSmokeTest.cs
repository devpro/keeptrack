using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Pages;
using Keeptrack.Testing.Shared.Authentication;
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
        // The shared Page and Context (SmokeTestBase.ContextOptions) carry a signed-in storage state, so an anonymous visit needs its own context with none.
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
    /// <c>FirebaseAuthenticationController.Callback</c> itself has no test below the browser:
    /// every other test here reaches it only through the fixture's own sign-in setup with a genuinely valid token.
    /// These three exercise its own validation, over a direct POST rather than a page navigation.
    /// </summary>
    [Fact]
    public async Task Callback_WithNoToken_Answers400()
    {
        SkipUnlessFirebase();

        var response = await Context.APIRequest.PostAsync("/auth/callback",
            new APIRequestContextOptions { DataObject = new { idToken = "" } });

        Assert.Equal(400, response.Status);
    }

    [Fact]
    public async Task Callback_WithAnInvalidToken_Answers401()
    {
        SkipUnlessFirebase();

        var response = await Context.APIRequest.PostAsync("/auth/callback",
            new APIRequestContextOptions { DataObject = new { idToken = "not-a-real-firebase-token" } });

        Assert.Equal(401, response.Status);
    }

    /// <summary>
    /// The shared context's storage state is a signed-in session,
    /// so this needs its own anonymous one to prove the "must already be signed in" check, same reasoning as the anonymous-visit test above.
    /// </summary>
    [Fact]
    public async Task Refresh_WhenNotSignedIn_Answers401()
    {
        SkipUnlessFirebase();

        var anonymousPage = await NewAnonymousPageAsync("refresh-unauthenticated");

        var response = await anonymousPage.Context.APIRequest.PostAsync("/auth/refresh",
            new APIRequestContextOptions { DataObject = new { idToken = "irrelevant" } });

        Assert.Equal(401, response.Status);
    }

    /// <summary>
    /// The core guard in <c>FirebaseAuthenticationController.Refresh</c>:
    /// a token that verifies fine but belongs to a different Firebase user must never be allowed to swap the identity behind an existing session.
    /// </summary>
    [Fact]
    public async Task Refresh_WithAnotherUsersValidToken_Answers401()
    {
        SkipUnlessFirebase();

        var anotherUsersToken = await Fixture.GetAnotherUsersIdTokenAsync();
        Assert.SkipWhen(anotherUsersToken is null,
            "Minting a second identity needs the in-process Blazor host's own Firebase Admin SDK access (self-hosted integration mode only).");

        // The shared context is already signed in as the run's own identity.
        var response = await Context.APIRequest.PostAsync("/auth/refresh",
            new APIRequestContextOptions { DataObject = new { idToken = anotherUsersToken } });

        Assert.Equal(401, response.Status);
    }

    /// <summary>
    /// Signs in as the run's own identity, so whatever the pages write for it is removed with the fixture's other documents.
    /// </summary>
    [Fact]
    public async Task LocalSignIn_ThroughTheForm_ReturnsToTheRequestedPage()
    {
        SkipUnlessLocal();
        var anonymousPage = await NewAnonymousPageAsync("local-sign-in");
        await anonymousPage.GotoAsync("/books");
        var login = new LoginPage(anonymousPage);
        await login.WaitForReadyAsync();

        await login.SignInLocallyAsync(Fixture.SignedInEmail, "Admin");

        await Assertions.Expect(anonymousPage).ToHaveURLAsync(new Regex("/books$"));
    }

    [Fact]
    public async Task LocalSignIn_WithNoEmail_Answers400()
    {
        SkipUnlessLocal();

        var response = await Context.APIRequest.PostAsync("/auth/local",
            new APIRequestContextOptions { DataObject = new { email = "", role = "admin" } });

        Assert.Equal(400, response.Status);
    }

    /// <summary>
    /// The password-less local sign-in must never answer on a Firebase host (see <c>AuthenticationModeControllerFilterTest</c> for both directions).
    /// Asserted through its effect rather than a status code, since an unknown path is re-executed as a POST to the not-found page, which Blazor's form handling answers 400.
    /// </summary>
    [Fact]
    public async Task LocalSignIn_DoesNotSignIn_OnAFirebaseHost()
    {
        SkipUnlessFirebase();
        var anonymousPage = await NewAnonymousPageAsync("local-sign-in-on-firebase");

        var response = await anonymousPage.Context.APIRequest.PostAsync("/auth/local",
            new APIRequestContextOptions { DataObject = new { email = "intruder@keeptrack.test", role = "admin" } });
        await anonymousPage.GotoAsync("/books");

        Assert.NotEqual(200, response.Status);
        await new LoginPage(anonymousPage).WaitForReadyAsync();
    }

    private static void SkipUnlessFirebase() =>
        Assert.SkipWhen(TestAuthentication.IsLocal, "Firebase sign-in only, and this run uses local authentication.");

    private static void SkipUnlessLocal() =>
        Assert.SkipUnless(TestAuthentication.IsLocal, "Local sign-in only, and this run uses Firebase authentication.");
}
