using System.Threading.Tasks;
using Keeptrack.BlazorApp.E2eTests.Hosting;
using Keeptrack.BlazorApp.E2eTests.Pages;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.E2eTests.Smoke;

[Trait("Category", "E2eTests")]
[Trait("Mode", "Readonly")]
public class AuthSmokeTest(E2eFixture fixture) : SmokeTestBase(fixture)
{
    [Fact]
    public async Task AnonymousVisit_ToProtectedPage_RedirectsToLogin()
    {
        // The shared Page/Context (from SmokeTestBase.ContextOptions) already carries a signed-in storage
        // state - a genuinely anonymous visit needs its own context with none, per the e2e plan ("only the
        // dedicated auth test uses a clean context").
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
        await Page.GotoAsync("/");
        await Page.GetByRole(AriaRole.Link, new() { Name = "Log out" }).ClickAsync();

        await Page.GotoAsync("/books");

        await new LoginPage(Page).WaitForReadyAsync();
    }
}
