using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Keeptrack.Common.System;
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

    private readonly List<Func<Task>> _cleanups = [];

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

        // Cleanup runs before the diagnostics below so a failure to remove data can't be skipped by an
        // error while capturing a screenshot or trace. Failures are reported rather than swallowed
        // (Fixture.DeleteItemAsync already logs and absorbs per-item HTTP errors).
        for (var i = _cleanups.Count - 1; i >= 0; i--)
        {
            await _cleanups[i]();
        }

        _cleanups.Clear();

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
    /// Registers an undo action to run when the test ends, whether it passed or failed.
    /// <para>
    /// A smoke test drives the real UI, so its data is created several assertions before the test's own
    /// delete step at the end - and every assertion in between is a place the test can stop early, leaving
    /// the item behind. That isn't hypothetical: <c>E2e Smoke Collectible</c> and <c>E2e Smoke Gear</c>
    /// documents from abandoned runs were found in a real database. Registering at creation time closes the
    /// window; a test that also deletes through the UI is unaffected, since deleting twice is a no-op.
    /// </para>
    /// </summary>
    protected void TrackCleanup(Func<Task> cleanup) => _cleanups.Add(cleanup);

    /// <summary>
    /// Registers the item whose detail page is currently open, by reading its id out of the page URL - the
    /// only place a UI-driven test can learn it (see <see cref="ExtractIdFromUrl"/>). Call it as soon as
    /// the detail page is ready, not at the end of the test.
    /// </summary>
    protected void TrackOpenItem(string apiRoute)
    {
        var resourcePathAndId = $"{apiRoute.TrimEnd('/')}/{ExtractIdFromUrl(Page.Url)}";
        TrackCleanup(() => Fixture.DeleteItemAsync(resourcePathAndId));
    }

    /// <summary>
    /// Creates an item straight through the API - for the setup a test needs but isn't itself testing (a
    /// movie to share, a show for Watch Next to pick up) - and registers it for deletion in one step.
    /// <para>
    /// Several smoke tests had grown their own copy of this POST-and-deserialize helper; it lives here once
    /// so seeding through the API always tracks what it created, rather than depending on each test
    /// remembering to.
    /// </para>
    /// </summary>
    protected async Task<T> CreateItemAsync<T>(string apiRoute, T body)
        where T : IHasId
    {
        var response = await Fixture.ApiHttpClient.PostAsJsonAsync(apiRoute, body, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var created = (await response.Content.ReadFromJsonAsync<T>(TestContext.Current.CancellationToken))!;
        TrackCleanup(() => Fixture.DeleteItemAsync($"{apiRoute.TrimEnd('/')}/{created.Id}"));
        return created;
    }

    /// <summary>
    /// Registers everything a list query returns at cleanup time - for the import smoke tests, whose commit
    /// creates items the test never sees the ids of.
    /// </summary>
    protected void TrackItemsMatching(string apiRoute, string listQueryUrl)
    {
        TrackCleanup(async () =>
        {
            foreach (var id in await Fixture.GetItemIdsAsync(listQueryUrl))
            {
                await Fixture.DeleteItemAsync($"{apiRoute.TrimEnd('/')}/{id}");
            }
        });
    }

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
