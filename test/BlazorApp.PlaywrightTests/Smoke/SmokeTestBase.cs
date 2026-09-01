using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Keeptrack.Common.System;
using Keeptrack.Testing.Shared.Hosting;
using Microsoft.Playwright;
using Microsoft.Playwright.Xunit.v3;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Smoke;

/// <summary>
/// Shared setup for every smoke test class: the E2E_ENABLED skip guard,
/// a pre-authenticated browser context (via <see cref="End2EndFixture"/>'s storage state, captured once for the whole run),
/// headless/slowmo/browser selection from <see cref="End2EndConfiguration"/>, and failure diagnostics (trace + screenshot).
/// <para>
/// Every Playwright test class in this suite derives from here, so every one of them leaves a full-page screenshot
/// of each open page - plus the Playwright trace, unless <c>E2E_TRACE=off</c> - in <c>e2e-diagnostics</c> under the
/// test output directory (<c>test/BlazorApp.PlaywrightTests/bin/&lt;config&gt;/net10.0/e2e-diagnostics</c>) whenever it fails.
/// The paths are printed to the failing test's output, so a CI log names the files rather than only the assertion.
/// </para>
/// </summary>
public abstract partial class SmokeTestBase : PageTest
{
    private bool _tracingStarted;

    private readonly List<Func<Task>> _cleanups = [];

    /// <summary>
    /// Every browser context this test drives: the shared signed-in one first, then any opened through
    /// <see cref="NewAnonymousPageAsync"/>. The failure diagnostics walk this list rather than only
    /// <see cref="PageTest.Page"/>, so a test whose subject is an anonymous page is diagnosed from *that* page.
    /// </summary>
    private readonly List<(string? Label, IBrowserContext Context)> _trackedContexts = [];

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

        _tracingStarted = End2EndConfiguration.Trace != TraceMode.Off;
        await TrackContextAsync(null, Context);
    }

    public override async ValueTask DisposeAsync()
    {
        var failed = TestContext.Current.TestState?.Result == TestResult.Failed;

        // Cleanup runs before the diagnostics below so a failure to remove data can't be skipped by an error while capturing a screenshot or trace.
        // Failures are reported rather than swallowed (Fixture.DeleteItemAsync already logs and absorbs per-item HTTP errors).
        for (var i = _cleanups.Count - 1; i >= 0; i--)
        {
            await _cleanups[i]();
        }

        _cleanups.Clear();

        await CaptureDiagnosticsAsync(failed);

        // base.DisposeAsync closes every context opened through NewContext, so the diagnostics above have to run first.
        // That is the whole reason NewAnonymousPageAsync exists instead of a per-test `await using`.
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
    /// Opens a page in a brand-new context carrying none of the run's signed-in storage state: an anonymous visitor, a share recipient,
    /// or a browser supplying its own forged cookie.
    /// <para>
    /// Four tests each built that context by hand and disposed it at the end of the test body,
    /// which put the very page under test out of reach of the failure diagnostics:
    /// on a failure they screenshotted the untouched shared page instead, and traced only the context nothing had happened in.
    /// Opening it here keeps it alive until <see cref="DisposeAsync"/> (Playwright's own <c>NewContext</c> closes it afterward)
    /// and registers it for capture, so an anonymous-page test is diagnosed like every other one.
    /// </para>
    /// </summary>
    /// <param name="label">Distinguishes this page's diagnostics files from the shared page's.</param>
    protected async Task<IPage> NewAnonymousPageAsync(string label = "anonymous")
    {
        var context = await NewContext(new BrowserNewContextOptions
        {
            BaseURL = Fixture.BlazorBaseUrl,
            IgnoreHTTPSErrors = true
        });
        await TrackContextAsync(label, context);
        return await context.NewPageAsync();
    }

    /// <summary>
    /// Read-only mode skips every mutating test (add/edit/delete/reference-linking), called at the top of any such test.
    /// </summary>
    protected static void SkipIfReadOnly()
    {
        Assert.SkipWhen(End2EndConfiguration.ReadOnly, "E2E_READONLY is set; mutating test skipped.");
    }

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
        => TrackCleanup(() => RemoveItemsMatchingAsync(apiRoute, listQueryUrl));

    /// <summary>
    /// The immediate form of <see cref="TrackItemsMatching"/>, for a test that needs the tenant in a known
    /// state *before* it starts rather than after it finishes.
    /// <para>
    /// Deleting something the test didn't create is normally forbidden here, and this is the one narrow
    /// exception: a scenario whose precondition is "the tenant does not already hold this item" cannot be set
    /// up any other way (Explore's add, where the feature's whole contract is to hide what you already track).
    /// It is safe only because <see cref="TestDatabaseGuard"/> refuses to let the suite run against anything
    /// but a dedicated test database - never <c>keeptrack_dev</c> or a real one. Match as narrowly as the list
    /// query allows, and never reach for this to paper over a missing cleanup.
    /// </para>
    /// </summary>
    protected async Task RemoveItemsMatchingAsync(string apiRoute, string listQueryUrl)
    {
        foreach (var id in await Fixture.GetItemIdsAsync(listQueryUrl))
        {
            await Fixture.DeleteItemAsync($"{apiRoute.TrimEnd('/')}/{id}");
        }
    }

    /// <summary>
    /// A detail page's own URL (e.g. "/movies/{id}") is the only place a smoke test can read the id it needs
    /// for direct-API cleanup, since the Add form's response body isn't surfaced anywhere in the UI.
    /// </summary>
    protected static string ExtractIdFromUrl(string url) => new Uri(url).Segments[^1].TrimEnd('/');

    private async Task TrackContextAsync(string? label, IBrowserContext context)
    {
        _trackedContexts.Add((label, context));

        if (_tracingStarted)
        {
            await context.Tracing.StartAsync(new TracingStartOptions { Screenshots = true, Snapshots = true, Sources = true });
        }
    }

    /// <summary>
    /// Writes a full-page screenshot of every page the test left open (plus the trace, when kept) to <see cref="DiagnosticsDirectory"/>, and prints where they went.
    /// A failing CI run should name its own evidence rather than leave the reader to know the convention.
    /// </summary>
    private async Task CaptureDiagnosticsAsync(bool failed)
    {
        var keepTrace = _tracingStarted && (failed || End2EndConfiguration.Trace == TraceMode.On);
        var directory = DiagnosticsDirectory();
        if (failed || keepTrace)
        {
            Directory.CreateDirectory(directory);
        }

        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var written = new List<string>();

        foreach (var (label, context) in _trackedContexts)
        {
            if (failed)
            {
                // Pages, not Page: a test can drive several (a share recipient's tab alongside the owner's), and the failing assertion is as likely to be on the second one.
                foreach (var page in context.Pages.Where(page => !page.IsClosed))
                {
                    var path = DiagnosticFilePath(usedNames, directory, label, ".png");
                    if (await TryCaptureAsync(() => page.ScreenshotAsync(new PageScreenshotOptions { Path = path, FullPage = true }), "the screenshot"))
                    {
                        written.Add(path);
                    }
                }
            }

            if (!_tracingStarted)
            {
                continue;
            }

            if (keepTrace)
            {
                var path = DiagnosticFilePath(usedNames, directory, label, ".zip");
                if (await TryCaptureAsync(() => context.Tracing.StopAsync(new TracingStopOptions { Path = path }), "the trace"))
                {
                    written.Add(path);
                }
            }
            else
            {
                await TryCaptureAsync(() => context.Tracing.StopAsync(), "discarding the trace");
            }
        }

        _trackedContexts.Clear();

        if (written.Count > 0)
        {
            Report($"E2E diagnostics written to {directory}: {string.Join(", ", written.Select(Path.GetFileName))}");
        }
    }

    /// <summary>
    /// Capturing diagnostics may never replace the test's own failure, nor cost the trace that would explain it:
    /// a page that is mid-navigation or already crashed throws here,
    /// and that exception would become the reported result of a test that failed for an entirely different reason.
    /// </summary>
    private static async Task<bool> TryCaptureAsync(Func<Task> capture, string what)
    {
        try
        {
            await capture();
            return true;
        }
        catch (Exception exception)
        {
            Report($"E2E diagnostics: {what} failed - {exception.Message}");
            return false;
        }
    }

    /// <summary>
    /// The test's own output when it is still collecting (that is where a CI log shows it, next to the assertion), the console otherwise.
    /// A run that reached its diagnostics must never fail on the act of reporting them.
    /// </summary>
    private static void Report(string message)
    {
        try
        {
            if (TestContext.Current.TestOutputHelper is { } output)
            {
                output.WriteLine(message);
                return;
            }
        }
        catch (InvalidOperationException)
        {
        }

        Console.WriteLine(message);
    }

    private static string DiagnosticsDirectory() => Path.Combine(AppContext.BaseDirectory, "e2e-diagnostics");

    /// <summary>
    /// "{test}.png" for the shared page, "{test}-{label}.png" for an extra context's, numbered from 2 if a test opens several under the same label.
    /// One file per page, so none of them silently overwrites another.
    /// </summary>
    private static string DiagnosticFilePath(HashSet<string> usedNames, string directory, string? label, string extension)
    {
        var baseName = label is null ? TestFileName() : $"{TestFileName()}-{label}";
        var name = baseName;
        for (var index = 2; !usedNames.Add($"{name}{extension}"); index++)
        {
            name = $"{baseName}-{index}";
        }

        return Path.Combine(directory, $"{name}{extension}");
    }

    private static string TestFileName()
    {
        var name = TestContext.Current.Test?.TestDisplayName ?? "test";
        return Path.GetInvalidFileNameChars().Aggregate(name, (current, c) => current.Replace(c, '_'));
    }
}
