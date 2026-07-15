extern alias WebApiHost;
extern alias BlazorHost;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using FirebaseAdmin.Auth;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Keeptrack.Testing.Shared.Firebase;
using Keeptrack.Testing.Shared.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Playwright;
using Xunit;

namespace Keeptrack.BlazorApp.PlaywrightTests.Hosting;

/// <summary>
/// Assembly-wide setup for the whole e2e run (xunit v3 <c>[assembly: AssemblyFixture(typeof(E2eFixture))]</c>,
/// see AssemblyInfo.cs): resolves the run mode, hosts both apps in-process (or targets a live deployment),
/// signs in exactly once, and seeds deterministic reference data. Every smoke test class takes this as a
/// constructor parameter and reuses the single instance - critically, this means the whole run performs at
/// most one real Firebase sign-in and one ephemeral-user creation, not one per test class.
/// </summary>
public sealed class E2eFixture : IAsyncLifetime
{
    /// <summary>
    /// Not part of the public E2E_* configuration surface (see <see cref="E2eConfiguration"/>) - these just
    /// satisfy <see cref="KestrelWebAppFactory{TEntryPoint}"/>'s constructor contract for the "point at an
    /// already-running instance" escape hatch. Self-hosted e2e mode always wants a fresh dynamic-port host,
    /// so nobody is expected to ever set them; live mode (E2E_TARGET_URL) is the supported way to target an
    /// already-running deployment.
    /// </summary>
    private const string WebApiKestrelUrlOverride = "E2E_INTERNAL_WEBAPI_KESTREL_URL";

    private const string BlazorKestrelUrlOverride = "E2E_INTERNAL_BLAZOR_KESTREL_URL";

    private KestrelWebAppFactory<WebApiHost::Program>? _webApiFactory;
    private KestrelWebAppFactory<BlazorHost::Program>? _blazorFactory;
    private IPlaywright? _playwright;
    private string? _ephemeralUserUid;
    private string _idToken = "";

    public string BlazorBaseUrl { get; private set; } = "";

    public string WebApiBaseUrl { get; private set; } = "";

    public string StorageStatePath { get; private set; } = "";

    public async ValueTask InitializeAsync()
    {
        // Nothing here matters when disabled - every test's own SmokeTestBase.InitializeAsync dynamically
        // skips before touching any of this, so there is no point spinning up hosts/browsers/Firebase calls
        // just for them to go unused. This keeps a plain solution-wide `dotnet test` fast, not just green.
        if (!E2eConfiguration.Enabled) return;

        if (E2eConfiguration.IsLiveMode)
        {
            BlazorBaseUrl = E2eConfiguration.TargetUrl!;
            if (!E2eConfiguration.ReadOnly)
            {
                WebApiBaseUrl = E2eConfiguration.WebApiUrl
                    ?? throw new InvalidOperationException("E2E_WEBAPI_URL is required in live mode unless E2E_READONLY is set.");
            }
        }
        else
        {
            _webApiFactory = new KestrelWebAppFactory<WebApiHost::Program>(
                WebApiKestrelUrlOverride,
                new KeyValuePair<string, string?>("Features:IsReferenceSyncEnabled", "false"));
            WebApiBaseUrl = _webApiFactory.ServerAddress;

            // The hosted Blazor app needs WebApi:BaseUrl injected with the WebApi host's own dynamic address -
            // but BlazorApp's Program.cs reads it via builder.Configuration.TryGetSection(...) *before*
            // WebApplicationBuilder.Build() runs, which is earlier than WebApplicationFactory's own
            // ConfigureWebHost/ConfigureAppConfiguration override can reach (that override only affects the
            // configuration used *after* Build()). Confirmed against a real run: passing this the same way
            // as the WebApi factory's Features:IsReferenceSyncEnabled override below left the Blazor host
            // silently dialing its static appsettings.Development.json WebApi:BaseUrl instead. A real process
            // environment variable is read synchronously by WebApplication.CreateBuilder itself, so it's
            // visible in time.
            Environment.SetEnvironmentVariable("WebApi__BaseUrl", WebApiBaseUrl);
            _blazorFactory = new KestrelWebAppFactory<BlazorHost::Program>(BlazorKestrelUrlOverride);
            BlazorBaseUrl = _blazorFactory.ServerAddress;

            EnsureReferenceProviderKeysConfigured();
        }

        var (username, password) = await ResolveCredentialsAsync();

        _idToken = await AccountRepository.AuthenticateAsync(username, password, FirebaseConfiguration.ApplicationKey)
                   ?? throw new InvalidOperationException("Firebase sign-in did not return an id token.");

        _playwright = await Playwright.CreateAsync();
        StorageStatePath = Path.Combine(Path.GetTempPath(), $"keeptrack-e2e-storage-{Guid.NewGuid():N}.json");
        await SignInAndSaveStorageStateAsync();

        if (!E2eConfiguration.ReadOnly)
        {
            await SeedReferenceDataAsync();
        }
    }

    /// <summary>
    /// Movie/TvShow/VideoGame/Album smoke tests link real, well-known titles against the real TMDB/RAWG/
    /// Discogs providers (Book/Open Library needs no key) - fail fast with a clear, actionable error rather
    /// than letting those tests fail downstream with a confusing "no results found". Only checked in
    /// self-hosted integration mode, since a live deployment's configuration can't be inspected this way -
    /// live mode trusts the deployment is already configured correctly.
    /// </summary>
    private void EnsureReferenceProviderKeysConfigured()
    {
        var configuration = _webApiFactory!.Services.GetRequiredService<IConfiguration>();
        var missingVariables = new (string ConfigKey, string EnvVarName)[]
        {
            ("Tmdb:ApiKey", "Tmdb__ApiKey"),
            ("Rawg:ApiKey", "Rawg__ApiKey"),
            ("Discogs:Token", "Discogs__Token")
        }.Where(x => string.IsNullOrEmpty(configuration[x.ConfigKey])).Select(x => x.EnvVarName).ToList();

        if (missingVariables.Count > 0)
        {
            throw new InvalidOperationException(
                $"Missing required reference-provider configuration for e2e tests: {string.Join(", ", missingVariables)}. " +
                "Movie/TvShow/VideoGame/Album smoke tests link real titles against real TMDB/RAWG/Discogs providers.");
        }
    }

    /// <summary>
    /// An explicit E2E_USERNAME always wins (works in every mode). Otherwise, integration mode creates its
    /// own ephemeral admin user - live mode and read-only mode both require an explicit account, since
    /// neither creates or cleans up a throwaway Firebase user.
    /// </summary>
    private async Task<(string Username, string Password)> ResolveCredentialsAsync()
    {
        if (!string.IsNullOrEmpty(E2eConfiguration.Username))
        {
            var password = E2eConfiguration.Password
                ?? throw new InvalidOperationException("E2E_PASSWORD is required when E2E_USERNAME is set.");
            return (E2eConfiguration.Username, password);
        }

        if (E2eConfiguration.IsLiveMode)
        {
            throw new InvalidOperationException("E2E_USERNAME/E2E_PASSWORD are required in live mode (E2E_TARGET_URL).");
        }

        if (E2eConfiguration.ReadOnly)
        {
            throw new InvalidOperationException(
                "E2E_READONLY requires an existing E2E_USERNAME/E2E_PASSWORD account - no ephemeral user is created in read-only mode.");
        }

        // The Blazor host (already started above) initialized FirebaseApp.DefaultInstance from its own
        // Firebase:ServiceAccount configuration (see src/BlazorApp/Program.cs) - reused here rather than
        // parsing the service account credential a second time.
        var email = $"e2e-{Guid.NewGuid():N}@keeptrack.test";
        var password2 = $"E2e-{Guid.NewGuid():N}!Aa1";
        var user = await FirebaseAuth.DefaultInstance.CreateUserAsync(new UserRecordArgs
        {
            Email = email,
            Password = password2,
            EmailVerified = true
        });
        await FirebaseAuth.DefaultInstance.SetCustomUserClaimsAsync(user.Uid, new Dictionary<string, object> { ["role"] = "admin" });
        _ephemeralUserUid = user.Uid;
        return (email, password2);
    }

    /// <summary>
    /// Programmatic sign-in: the login page is OAuth-popup-only and cannot be automated (see the e2e plan),
    /// but <c>POST /auth/callback</c> accepts any verified Firebase ID token. Captured once as Playwright
    /// storage state so every smoke test starts already signed in without repeating this per test/class.
    /// </summary>
    private async Task SignInAndSaveStorageStateAsync()
    {
        await using var apiRequestContext = await _playwright!.APIRequest.NewContextAsync(new APIRequestNewContextOptions
        {
            BaseURL = BlazorBaseUrl,
            IgnoreHTTPSErrors = true
        });

        var response = await apiRequestContext.PostAsync("/auth/callback", new APIRequestContextOptions
        {
            DataObject = new { idToken = _idToken }
        });
        if (!response.Ok)
        {
            throw new InvalidOperationException($"POST /auth/callback failed with {response.Status}: {await response.TextAsync()}");
        }

        await apiRequestContext.StorageStateAsync(new APIRequestContextStorageStateOptions { Path = StorageStatePath });
    }

    /// <summary>
    /// The deterministic "look for a ref" path: import a synthetic reference document via the same admin
    /// endpoint a real export/import round-trip uses, so <c>ReferenceSmokeTest</c>'s "check for reference
    /// match" click only ever queries MongoDB, never a real provider.
    /// </summary>
    private async Task SeedReferenceDataAsync()
    {
        var zip = ReferenceFixtureZipBuilder.Build();

        using var httpClient = new HttpClient { BaseAddress = new Uri(WebApiBaseUrl) };
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _idToken);

        using var content = new MultipartFormDataContent();
        using var fileContent = new ByteArrayContent(zip);
        content.Add(fileContent, "file", "keeptrack-e2e-reference-data.zip");

        var response = await httpClient.PostAsync("/api/reference-data/import", content);
        response.EnsureSuccessStatusCode();
    }

    private HttpClient? _apiHttpClient;

    /// <summary>
    /// <see cref="E2eFixture"/> is a single instance shared by every parallel-running smoke test class, and
    /// several of them call <see cref="DeleteItemAsync"/> from their own cleanup - a plain <c>??=</c> lazy-init
    /// here is not thread-safe against that, confirmed by a real intermittent failure under a full parallel
    /// run. <see cref="LazyInitializer.EnsureInitialized{T}(ref T?, Func{T})"/> is the same thread-safe pattern
    /// <c>Testing.Shared</c>'s own <c>AccountRepository.AuthenticateAsync</c> already uses for exactly this
    /// kind of shared, lazily-created, concurrently-accessed resource. Public so a test that needs direct,
    /// signed-in API access beyond <see cref="DeleteItemAsync"/> (e.g. <c>MobileScreenshotTest</c>'s seeding)
    /// reuses the run's one authenticated identity instead of re-deriving credentials itself - which would
    /// silently break in ephemeral-user mode, where no E2E_USERNAME exists to re-derive from.
    /// </summary>
    public HttpClient ApiHttpClient => LazyInitializer.EnsureInitialized(ref _apiHttpClient, () =>
    {
        var client = new HttpClient { BaseAddress = new Uri(WebApiBaseUrl) };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _idToken);
        return client;
    });

    /// <summary>
    /// Deletes an item directly via the API rather than through the UI - meant to be called from a smoke
    /// test's own <c>finally</c> block, so a mid-test assertion failure still cleans up. This matters more
    /// here than it did for Book's phase-2 tests: Movie/TvShow/VideoGame/Album smoke tests use fixed,
    /// recognizable real-world titles (not a random GUID) so the reference-provider search means something,
    /// which makes an orphaned leftover from a failed run an actual accumulating duplicate, not just harmless
    /// clutter with a never-repeated name.
    /// </summary>
    public async Task DeleteItemAsync(string resourcePathAndId)
    {
        try
        {
            await ApiHttpClient.DeleteAsync(resourcePathAndId);
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"Failed to clean up {resourcePathAndId}: {ex.Message}");
        }
    }

    public async ValueTask DisposeAsync()
    {
        _apiHttpClient?.Dispose();

        if (_ephemeralUserUid is not null)
        {
            try
            {
                await FirebaseAuth.DefaultInstance.DeleteUserAsync(_ephemeralUserUid);
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"Failed to delete ephemeral e2e user {_ephemeralUserUid}: {ex.Message}");
            }
        }

        _playwright?.Dispose();

        if (_blazorFactory is not null) await _blazorFactory.DisposeAsync();
        if (_webApiFactory is not null) await _webApiFactory.DisposeAsync();

        if (!string.IsNullOrEmpty(StorageStatePath) && File.Exists(StorageStatePath))
        {
            try
            {
                File.Delete(StorageStatePath);
            }
            catch (IOException)
            {
                // best-effort cleanup of a temp file - not worth failing the run over.
            }
        }
    }
}
