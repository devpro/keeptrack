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
        await using var anonymousContext = await NewContext(new BrowserNewContextOptions
        {
            BaseURL = Fixture.BlazorBaseUrl,
            IgnoreHTTPSErrors = true
        });
        var anonymousPage = await anonymousContext.NewPageAsync();

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
}
