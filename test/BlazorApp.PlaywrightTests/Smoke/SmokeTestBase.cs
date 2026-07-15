using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Microsoft.Playwright;
using Microsoft.Playwright.Xunit.v3;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Shared setup for every smoke test class: the E2E_ENABLED skip guard,
/// a pre-authenticated browser context (via <see cref="End2EndFixture"/>'s storage state, captured once for the whole run),
/// headless/slowmo/browser selection from <see cref="End2EndConfiguration"/>, and failure diagnostics (trace + screenshot).
/// </summary>
public abstract partial class SmokeTestBase : PageTest
{
    private bool _tracingStarted;

    protected End2EndFixture Fixture { get; }

    protected SmokeTestBase(End2EndFixture fixture)
    {
        Fixture = fixture;
        // BrowserType selection (Microsoft.Playwright.Xunit.v3's own PlaywrightSettingsProvider.BrowserName)
        // has no supported extension point beyond the native BROWSER environment variable it reads live on every InitializeAsync,
        // so E2E_BROWSER is translated into it here rather than duplicating browser-selection logic.
        Environment.SetEnvironmentVariable("BROWSER", End2EndConfiguration.Browser);
    }

    public override async ValueTask InitializeAsync()
    {
        Assert.SkipUnless(End2EndConfiguration.Enabled, "E2E_ENABLED is not set; e2e tests are disabled.");

        await base.InitializeAsync();

        if (End2EndConfiguration.Trace != TraceMode.Off)
        {
            await Context.Tracing.StartAsync(new TracingStartOptions { Screenshots = true, Snapshots = true, Sources = true });
            _tracingStarted = true;
        }
    }

    public override async ValueTask DisposeAsync()
    {
        var failed = TestContext.Current.TestState?.Result == TestResult.Failed;

        if (failed)
        {
            var dir = DiagnosticsDirectory();
            Directory.CreateDirectory(dir);
            await Page.ScreenshotAsync(new PageScreenshotOptions { Path = Path.Combine(dir, $"{TestFileName()}.png"), FullPage = true });
        }

        if (_tracingStarted)
        {
            if (failed || End2EndConfiguration.Trace == TraceMode.On)
            {
                var dir = DiagnosticsDirectory();
                Directory.CreateDirectory(dir);
                await Context.Tracing.StopAsync(new TracingStopOptions { Path = Path.Combine(dir, $"{TestFileName()}.zip") });
            }
            else
            {
                await Context.Tracing.StopAsync();
            }
        }

        await base.DisposeAsync();
    }

    public override BrowserNewContextOptions ContextOptions() => new()
    {
        BaseURL = Fixture.BlazorBaseUrl,
        StorageStatePath = Fixture.StorageStatePath,
        IgnoreHTTPSErrors = true
    };

    public override Task<BrowserTypeLaunchOptions?> LaunchOptionsAsync() => Task.FromResult<BrowserTypeLaunchOptions?>(new BrowserTypeLaunchOptions
    {
        Headless = End2EndConfiguration.Headless,
        SlowMo = End2EndConfiguration.SlowMoMs
    });

    /// <summary>
    /// Read-only mode skips every mutating test (add/edit/delete/reference-linking) - call at the top of any
    /// such test.
    /// </summary>
    protected static void SkipIfReadOnly()
        => Assert.SkipWhen(End2EndConfiguration.ReadOnly, "E2E_READONLY is set; mutating test skipped.");

    /// <summary>
    /// A detail page's own URL (e.g. "/movies/{id}") is the only place a smoke test can read the id it needs
    /// for direct-API cleanup, since the Add form's response body isn't surfaced anywhere in the UI.
    /// </summary>
    protected static string ExtractIdFromUrl(string url) => new Uri(url).Segments[^1].TrimEnd('/');

    private static string DiagnosticsDirectory() => Path.Combine(AppContext.BaseDirectory, "e2e-diagnostics");

    private static string TestFileName()
    {
        var name = TestContext.Current.Test?.TestDisplayName ?? "test";
        return Path.GetInvalidFileNameChars().Aggregate(name, (current, c) => current.Replace(c, '_'));
    }
}
