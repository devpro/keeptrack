using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using FirebaseAdmin.Auth;
using Keeptrack.BlazorApp.Components.Account;
using Keeptrack.BlazorApp.PlaywrightTests.Hosting;
using Keeptrack.BlazorApp.PlaywrightTests.Support;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Testing.Shared.Firebase;
using Keeptrack.Testing.Shared.Hosting;
using Keeptrack.WebApi.ReferenceData;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Playwright;
using MongoDB.Bson;
using MongoDB.Driver;
using Xunit;

[assembly: AssemblyFixture(typeof(End2EndFixture))]

namespace Keeptrack.BlazorApp.PlaywrightTests.Hosting;

/// <summary>
/// Assembly-wide setup for the whole e2e run (xunit v3 <c>[assembly: AssemblyFixture(typeof(End2EndFixture))]</c>): resolves the run mode, hosts both apps in-process (or targets a live deployment), signs in exactly once, and seeds deterministic reference data.
/// Every smoke test class takes this as a constructor parameter and reuses the single instance, so the whole run performs at most one real Firebase sign-in and one ephemeral-user creation.
/// </summary>
public sealed class End2EndFixture : IAsyncLifetime
{
    private const string WebApiKestrelUrlOverride = "E2E_INTERNAL_WEBAPI_KESTREL_URL";

    private const string BlazorKestrelUrlOverride = "E2E_INTERNAL_BLAZOR_KESTREL_URL";

    private KestrelWebAppFactory<Keeptrack.WebApi.Program>? _webApiFactory;

    private KestrelWebAppFactory<Program>? _blazorFactory;

    private IPlaywright? _playwright;

    private string? _ephemeralUserUid;

    private string? _secondEphemeralUserUid;

    private string? _secondEphemeralUserIdToken;

    private string _idToken = "";

    private string _webApiBaseUrl = "";

    public string BlazorBaseUrl { get; private set; } = "";

    public string StorageStatePath { get; private set; } = "";

    /// <summary>
    /// The email of the run's single signed-in identity: the ephemeral user's generated address in integration mode, or the configured E2E_USERNAME otherwise.
    /// The sharing smoke test self-shares to this address (the recipient is matched by email server-side), the same way ShareResourceTest uses FirebaseConfiguration.Username.
    /// </summary>
    public string SignedInEmail { get; private set; } = "";

    public async ValueTask InitializeAsync()
    {
        if (!End2EndConfiguration.Enabled) return;

        if (End2EndConfiguration.IsLiveMode)
        {
            BlazorBaseUrl = End2EndConfiguration.TargetUrl!;
            if (!End2EndConfiguration.ReadOnly)
            {
                _webApiBaseUrl = End2EndConfiguration.WebApiUrl
                                ?? throw new InvalidOperationException("E2E_WEBAPI_URL is required in live mode unless E2E_READONLY is set.");
            }
        }
        else
        {
            // Self-hosted mode runs the real WebApi against a real MongoDB, so it takes the integration suite's guard.
            // Without it, an unset Infrastructure__MongoDB__DatabaseName would point the whole e2e run at the developer's keeptrack_dev database.
            // Live mode is exempt, since the deployment owns its configuration and there is no local database to mis-target.
            // The name checked is the one this run uses, E2E_MONGODB_DATABASE's, not the ambient variable's (see End2EndConfiguration.DatabaseName).
            TestDatabaseGuard.EnsureTestDatabaseName(End2EndConfiguration.DatabaseName);

            _webApiFactory = new KestrelWebAppFactory<Keeptrack.WebApi.Program>(
                WebApiKestrelUrlOverride,
                new KeyValuePair<string, string?>("Features:IsReferenceSyncEnabled", "false"),
                new KeyValuePair<string, string?>("Infrastructure:MongoDB:DatabaseName", End2EndConfiguration.DatabaseName),
                // Pinned to igdb rather than inherited from appsettings.Development.json, so the suite doesn't drift with an unrelated deployment choice: IGDB is the more stable provider and is what VideoGameReferenceMatchSmokeTest is written against (it hard-requires Igdb__ClientId/ Igdb__ClientSecret but deliberately not Rawg__ApiKey).
                new KeyValuePair<string, string?>("ReferenceData:VideoGameProvider", "igdb"));
            _webApiBaseUrl = _webApiFactory.ServerAddress;

            // The hosted Blazor app needs WebApi:BaseUrl set to the WebApi host's dynamic address.
            // BlazorApp's Program.cs reads it through builder.Configuration.TryGetSection(...) before WebApplicationBuilder.Build(), earlier than WebApplicationFactory's ConfigureWebHost or ConfigureAppConfiguration override reaches.
            // Passed like the WebApi factory's Features:IsReferenceSyncEnabled override below, the Blazor host would dial its appsettings.Development.json WebApi:BaseUrl instead.
            // WebApplication.CreateBuilder reads a process environment variable synchronously, so it is visible in time.
            Environment.SetEnvironmentVariable("WebApi__BaseUrl", _webApiBaseUrl);
            _blazorFactory = new KestrelWebAppFactory<Program>(BlazorKestrelUrlOverride);
            BlazorBaseUrl = _blazorFactory.ServerAddress;

            EnsureReferenceProviderKeysConfigured();
        }

        var (username, password) = await ResolveCredentialsAsync();
        SignedInEmail = username;

        _idToken = await AccountRepository.AuthenticateAsync(username, password, FirebaseConfiguration.ApplicationKey)
                   ?? throw new InvalidOperationException("Firebase sign-in did not return an id token.");

        _playwright = await Playwright.CreateAsync();
        StorageStatePath = Path.Combine(Path.GetTempPath(), $"keeptrack-e2e-storage-{Guid.NewGuid():N}.json");
        await SignInAndSaveStorageStateAsync();

        if (!End2EndConfiguration.ReadOnly)
        {
            await SeedReferenceDataAsync();
        }
    }

    /// <summary>
    /// The movie, TV show, video game and album smoke tests link real, well-known titles against the real providers (Open Library needs no key).
    /// A missing key fails fast with a clear error rather than downstream with a confusing "no results found".
    /// Checked only in self-hosted integration mode, since a live deployment's configuration can't be inspected this way.
    /// </summary>
    private void EnsureReferenceProviderKeysConfigured()
    {
        var configuration = _webApiFactory!.Services.GetRequiredService<IConfiguration>();
        // the video game entry is IGDB's Twitch pair, not RAWG's key: what a smoke test links through is whichever provider is the *default*, and RAWG stopped being it.
        // RAWG is still registered (references linked through it keep their stored ratings), but no e2e path reaches it unless a test picks it explicitly, so requiring its key would fail runs for a provider they never call.
        var missingVariables = new (string ConfigKey, string EnvVarName)[]
            {
                ("Tmdb:ApiKey", "Tmdb__ApiKey"),
                ("Igdb:ClientId", "Igdb__ClientId"),
                ("Igdb:ClientSecret", "Igdb__ClientSecret"),
                ("Discogs:Token", "Discogs__Token")
            }
            .Where(x => string.IsNullOrEmpty(configuration[x.ConfigKey])).Select(x => x.EnvVarName).ToList();

        if (missingVariables.Count > 0)
        {
            throw new InvalidOperationException(
                $"Missing required reference-provider configuration for e2e tests: {string.Join(", ", missingVariables)}. " +
                "Movie/TvShow/VideoGame/Album smoke tests link real titles against real TMDB/IGDB/Discogs providers.");
        }
    }

    /// <summary>
    /// An explicit E2E_USERNAME always wins (works in every mode).
    /// Otherwise integration mode creates its own ephemeral admin user, while live and read-only modes require an explicit account, since neither creates or cleans up a throwaway Firebase user.
    /// </summary>
    private async Task<(string Username, string Password)> ResolveCredentialsAsync()
    {
        if (!string.IsNullOrEmpty(End2EndConfiguration.Username))
        {
            var password = End2EndConfiguration.Password
                           ?? throw new InvalidOperationException("E2E_PASSWORD is required when E2E_USERNAME is set.");
            return (End2EndConfiguration.Username, password);
        }

        if (End2EndConfiguration.IsLiveMode)
        {
            throw new InvalidOperationException("E2E_USERNAME/E2E_PASSWORD are required in live mode (E2E_TARGET_URL).");
        }

        if (End2EndConfiguration.ReadOnly)
        {
            throw new InvalidOperationException(
                "E2E_READONLY requires an existing E2E_USERNAME/E2E_PASSWORD account - no ephemeral user is created in read-only mode.");
        }

        // The Blazor host started above initialized FirebaseApp.DefaultInstance from its Firebase:ServiceAccount configuration (see src/BlazorApp/Program.cs), reused rather than parsing the credential again.
        var email = $"e2e-{Guid.NewGuid():N}@keeptrack.test";
        var password2 = $"E2e-{Guid.NewGuid():N}!Aa1";
        var user = await FirebaseAuth.DefaultInstance.CreateUserAsync(new UserRecordArgs { Email = email, Password = password2, EmailVerified = true });
        await FirebaseAuth.DefaultInstance.SetCustomUserClaimsAsync(user.Uid, new Dictionary<string, object> { ["role"] = "admin" });
        _ephemeralUserUid = user.Uid;
        return (email, password2);
    }

    /// <summary>
    /// Programmatic sign-in: the login page is OAuth-popup-only and cannot be automated (see the e2e plan), but <c>POST /auth/callback</c> accepts any verified Firebase ID token.
    /// Captured once as Playwright storage state so every smoke test starts already signed in without repeating this per test/class.
    /// </summary>
    private async Task SignInAndSaveStorageStateAsync()
    {
        await using var apiRequestContext = await _playwright!.APIRequest.NewContextAsync(new APIRequestNewContextOptions { BaseURL = BlazorBaseUrl, IgnoreHTTPSErrors = true });

        var response = await apiRequestContext.PostAsync("/auth/callback", new APIRequestContextOptions { DataObject = new { idToken = _idToken } });
        if (!response.Ok)
        {
            throw new InvalidOperationException($"POST /auth/callback failed with {response.Status}: {await response.TextAsync()}");
        }

        await apiRequestContext.StorageStateAsync(new APIRequestContextStorageStateOptions { Path = StorageStatePath });
    }

    /// <summary>
    /// The deterministic "look for a ref" path: imports a synthetic reference document through the admin endpoint a real export and import use.
    /// <c>ReferenceSmokeTest</c>'s "check for reference match" click then queries MongoDB only, never a real provider.
    /// <para>
    /// Re-seeding adds no second copy of the synthetic book, since the import matches on the fixture's Open Library id and updates the document carrying it (see <c>ReferenceDataImportService</c>).
    /// The first insert lands under the fixed <see cref="ReferenceFixtureZipBuilder.ReferenceId"/>, which is how <see cref="RemoveSeededReferenceDataAsync"/> knows what to delete.
    /// </para>
    /// </summary>
    private async Task SeedReferenceDataAsync()
    {
        var zip = ReferenceFixtureZipBuilder.Build();

        using var content = new MultipartFormDataContent();
        using var fileContent = new ByteArrayContent(zip);
        content.Add(fileContent, "file", "keeptrack-e2e-reference-data.zip");

        var response = await ApiHttpClient.PostAsync("/api/reference-data/import", content);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Removes the synthetic reference seeded above, so a run leaves the shared reference collections exactly as it found them.
    /// <para>
    /// It goes through the hosted <see cref="IBookReferenceRepository"/> rather than HTTP, since no admin endpoint deletes a single reference document.
    /// The only such path is a tenant item's <c>unlink-reference</c>, which needs a linked item, and a delete endpoint only for tests to tidy up would be the wrong trade.
    /// It is possible in self-hosted mode only, and in live mode the import's provider-id matching makes re-seeding a replace, so nothing accumulates there either.
    /// </para>
    /// Best effort and never fatal, since the run's results are in, and a teardown error shouldn't turn a green run red.
    /// </summary>
    private async Task RemoveSeededReferenceDataAsync()
    {
        if (_webApiFactory is null) return;

        try
        {
            using var scope = _webApiFactory.Services.CreateScope();
            var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
            await repository.DeleteAsync(ReferenceFixtureZipBuilder.ReferenceId);
        }
        catch (Exception exception)
        {
            await Console.Error.WriteLineAsync($"Failed to remove the seeded e2e reference data: {exception.Message}");
        }
    }

    /// <summary>
    /// Removes the documents the run's throwaway identity owns that no test can reach: its preferences (written the first time a page reads them) and its background-job rows (an import smoke test starts a job through the UI and never learns its id).
    /// Neither collection has a delete endpoint, and both are owner-scoped, so they're removed straight from MongoDB.
    /// <para>
    /// Deliberately guarded on <see cref="_ephemeralUserUid"/>: only an ephemeral user's documents are ever deleted here.
    /// When the run is pointed at a real account through <c>E2E_USERNAME</c>, this would otherwise wipe that person's own saved preferences.
    /// </para>
    /// </summary>
    private async Task RemoveEphemeralUserDocumentsAsync()
    {
        if (_ephemeralUserUid is null || _webApiFactory is null) return;

        try
        {
            var database = _webApiFactory.Services.GetRequiredService<IMongoDatabase>();
            foreach (var collectionName in new[] { "user_preference", "background_job" })
            {
                await database.GetCollection<BsonDocument>(collectionName)
                    .DeleteManyAsync(Builders<BsonDocument>.Filter.Eq("owner_id", _ephemeralUserUid));
            }
        }
        catch (Exception exception)
        {
            await Console.Error.WriteLineAsync($"Failed to remove the ephemeral e2e user's documents: {exception.Message}");
        }
    }

    /// <summary>
    /// Removes video game reference documents by id, for the one scenario whose premise is that no reference exists yet.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Reference documents resolved from a real provider are normally left in place on purpose: they are shared canonical facts, deduplicated by provider id, so a re-run reuses them and deleting only forces a re-fetch.
    /// This is the deliberate exception, and it is not tidiness.
    /// A test proving that matching reaches the <b>provider</b> can only observe it while nothing local answers, and by passing it creates such a local answer.
    /// Left behind, it would make the next run take the cheap local path, still green and no longer testing anything.
    /// With the provider escalation disabled, the video game matching scenarios would still pass against a database holding the last run's references.
    /// </para>
    /// <para>
    /// Self-hosted mode only, and silent when it cannot run (see <see cref="CanSeedDatabaseDirectly"/>).
    /// </para>
    /// </remarks>
    public Task RemoveVideoGameReferencesAsync(IEnumerable<string> referenceIds) =>
        RemoveReferencesAsync("videogame_reference", referenceIds);

    /// <summary>
    /// The same removal for any reference collection, since the other four domains have matching journeys of their own, whose references must go for the same reason.
    /// </summary>
    public async Task RemoveReferencesAsync(string collectionName, IEnumerable<string> referenceIds)
    {
        if (!CanSeedDatabaseDirectly) return;

        var ids = referenceIds.Where(id => !string.IsNullOrEmpty(id) && ObjectId.TryParse(id, out _)).Select(ObjectId.Parse).ToList();
        if (ids.Count == 0) return;

        try
        {
            var database = _webApiFactory!.Services.GetRequiredService<IMongoDatabase>();
            await database.GetCollection<BsonDocument>(collectionName)
                .DeleteManyAsync(Builders<BsonDocument>.Filter.In("_id", ids));
        }
        catch (Exception exception)
        {
            await Console.Error.WriteLineAsync($"Failed to remove e2e {collectionName} documents: {exception.Message}");
        }
    }

    /// <summary>
    /// Whether this run may write to MongoDB directly, in self-hosted mode only, since live mode (<c>E2E_TARGET_URL</c>) drives a remote deployment whose database this process can't reach.
    /// A test that needs it self-skips when it is false.
    /// </summary>
    public bool CanSeedDatabaseDirectly => _webApiFactory is not null;

    /// <summary>
    /// Writes entries into the shared, owner-less <c>explore_catalogue</c> so the Explore page has a deterministic ranking to render.
    /// <para>
    /// Straight through the hosted <see cref="IExploreCatalogueRepository"/>, unlike the reference seed above, which goes over HTTP.
    /// Only <c>ExploreCatalogueRefreshService</c> writes the catalogue, which this host never runs (<c>Features:IsReferenceSyncEnabled</c> is false), and which would call the real provider rankings.
    /// No admin endpoint writes one entry, and one only for test seeding would be the wrong trade, as with <see cref="RemoveSeededReferenceDataAsync"/>.
    /// </para>
    /// <para>
    /// The sync never running here is also what makes low ranks safe to seed: nothing else writes this collection, so a seeded ranking is the whole ranking and the page's first fetch shows it.
    /// </para>
    /// </summary>
    public async Task SeedExploreCatalogueAsync(IReadOnlyList<ExploreCatalogueEntryModel> entries)
    {
        using var scope = _webApiFactory!.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<IExploreCatalogueRepository>().UpsertManyAsync(entries);
    }

    /// <summary>
    /// Every ordering a domain's catalogue is maintained under, asked of the hosted app rather than hardcoded, since an entry filed under another ranking key is invisible to the page.
    /// Resolved from the API's container, since it depends on the deployment's discovery provider: movies and TV have one ordering, video games one per rating source IGDB supports.
    /// <para>
    /// All of them, not only the effective one: the page follows the admin-selected primary rating source, a stored setting no test controls, so a guessed seed would break where someone picked the other.
    /// </para>
    /// </summary>
    public IReadOnlyList<string> ExploreRankingsFor(ExploreItemType type)
    {
        using var scope = _webApiFactory!.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<ExploreRankings>().Rankings(type);
    }

    /// <summary>
    /// How many entries the shared catalogue holds, the premise every Explore smoke test rests on, a seeded ranking being the whole ranking (see <see cref="SeedExploreCatalogueAsync"/>).
    /// It breaks when the run shares its database with a suite whose <c>sync-now</c> tests rebuild the real TMDB ranking, and the symptom is a card count nobody can explain.
    /// </summary>
    public async Task<long> CountExploreCatalogueEntriesAsync()
    {
        var database = _webApiFactory!.Services.GetRequiredService<IMongoDatabase>();
        return await database.GetCollection<BsonDocument>("explore_catalogue")
            .CountDocumentsAsync(Builders<BsonDocument>.Filter.Empty);
    }

    /// <summary>
    /// Removes seeded catalogue entries by their provider ids.
    /// The repository only exposes the refresh pass's own "delete what I didn't rewrite" sweep, which would take the whole ranking with it, so this deletes exactly what the test created and nothing else.
    /// Best-effort like <see cref="DeleteItemAsync"/>: a teardown error shouldn't turn a green run red.
    /// </summary>
    public async Task RemoveExploreCatalogueEntriesAsync(IEnumerable<string> externalIds)
    {
        try
        {
            var database = _webApiFactory!.Services.GetRequiredService<IMongoDatabase>();
            await database.GetCollection<BsonDocument>("explore_catalogue")
                .DeleteManyAsync(Builders<BsonDocument>.Filter.In("external_id", externalIds));
        }
        catch (Exception exception)
        {
            await Console.Error.WriteLineAsync($"Failed to remove the seeded Explore catalogue entries: {exception.Message}");
        }
    }

    private HttpClient? _apiHttpClient;

    /// <summary>
    /// <see cref="End2EndFixture"/> is one instance shared by every parallel smoke test class, several of which call <see cref="DeleteItemAsync"/> from their cleanup, so a plain <c>??=</c> lazy init would race.
    /// <see cref="LazyInitializer.EnsureInitialized{T}(ref T?, Func{T})"/> is the thread-safe pattern <c>Testing.Shared</c>'s <c>AccountRepository.AuthenticateAsync</c> uses for the same kind of shared resource.
    /// Public, so a test needing signed-in API access beyond <see cref="DeleteItemAsync"/> (<c>MobileScreenshotTest</c>'s seeding) reuses the run's one identity.
    /// Re-deriving credentials would break in ephemeral-user mode, where no E2E_USERNAME exists.
    /// </summary>
    public HttpClient ApiHttpClient => LazyInitializer.EnsureInitialized(ref _apiHttpClient, () =>
    {
        var client = new HttpClient { BaseAddress = new Uri(_webApiBaseUrl) };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _idToken);
        return client;
    });

    /// <summary>
    /// Deletes an item through the API rather than the UI, from a smoke test's cleanup, so a mid-test assertion failure still cleans up.
    /// The movie, TV show, video game and album smoke tests use fixed real-world titles so the provider search means something.
    /// A leftover from a failed run is then an accumulating duplicate, not harmless clutter with a never-repeated name.
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

    /// <summary>
    /// Reads the ids of the items a paged list query returns (<c>"/api/books?search=..."</c>, <c>"/api/episodes?TvShowId=..."</c>), so an import smoke test can find what the commit created and delete it through <see cref="DeleteItemAsync"/>.
    /// Every list endpoint shares the one <c>PagedResult</c> shape, so this single helper serves all of them rather than a per-type variant.
    /// </summary>
    public async Task<IReadOnlyList<string>> GetItemIdsAsync(string listQueryUrl)
    {
        var page = await ApiHttpClient.GetFromJsonAsync<PagedItemIds>(listQueryUrl);
        return page?.Items.Where(item => item.Id is not null).Select(item => item.Id!).ToList() ?? [];
    }

    private sealed record PagedItemIds(List<ItemId> Items);

    private sealed record ItemId(string? Id);

    /// <summary>
    /// Forges a Blazor auth cookie whose principal is a fully-authorized member but whose stored Firebase token is a value WebApi rejects (a malformed JWT), reproducing a live session whose Firebase ID token has gone stale (expired or revoked) while the 8h auth cookie is still valid.
    /// The next server-rendered page's API call then answers 401, driving <c>AuthenticationTokenHandler.RedirectToLogin</c> during prerender, a path that must not throw "RemoteNavigationManager has not been initialized".
    /// Returns <c>null</c> in live mode (E2E_TARGET_URL), since forging the ticket needs the in-process Blazor host's data-protection keys, and the test self-skips there.
    /// </summary>
    public Cookie? ForgeStaleTokenMemberCookie()
    {
        if (_blazorFactory is null) return null;

        var cookieOptions = _blazorFactory.Services
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(CookieAuthenticationDefaults.AuthenticationScheme);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, _ephemeralUserUid ?? "e2e-forged-uid"),
            new(ClaimTypes.Name, SignedInEmail),
            new(ClaimTypes.Email, SignedInEmail),
            // Admin satisfies the shared-collection page's MemberOnly policy, so the page renders and makes its API call rather than being bounced by [Authorize].
            // That would exercise the cookie-challenge redirect rather than the stale-token one under test.
            new("role", "admin"),
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        var properties = new AuthenticationProperties
        {
            IsPersistent = true,
            IssuedUtc = DateTimeOffset.UtcNow,
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1),
        };
        properties.StoreTokens([
            new AuthenticationToken { Name = AuthenticationTokenHandler.FirebaseTokenName, Value = "stale.firebase.token" }
        ]);

        var ticket = new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme);

        return new Cookie
        {
            Name = cookieOptions.Cookie.Name!,
            Value = cookieOptions.TicketDataFormat!.Protect(ticket),
            Url = BlazorBaseUrl,
        };
    }

    /// <summary>
    /// A second, genuinely different Firebase identity's valid ID token, for the one test that proves <c>AuthenticationController.Refresh</c> refuses a token that verifies but belongs to someone else's session.
    /// Created once per run on first call and reused, the same lazy-and-cached shape as <see cref="ApiHttpClient"/>.
    /// Returns <c>null</c> for the same reason <see cref="ForgeStaleTokenMemberCookie"/> does: minting a user needs the in-process Blazor host's own Firebase Admin SDK access, which live and read-only mode don't have.
    /// </summary>
    public async Task<string?> GetAnotherUsersIdTokenAsync()
    {
        if (_blazorFactory is null) return null;

        if (_secondEphemeralUserUid is null)
        {
            var email = $"e2e-second-{Guid.NewGuid():N}@keeptrack.test";
            var password = $"E2e-{Guid.NewGuid():N}!Aa1";
            var user = await FirebaseAuth.DefaultInstance.CreateUserAsync(new UserRecordArgs { Email = email, Password = password, EmailVerified = true });
            _secondEphemeralUserUid = user.Uid;
            _secondEphemeralUserIdToken = await AccountRepository.AuthenticateAsync(email, password, FirebaseConfiguration.ApplicationKey)
                                           ?? throw new InvalidOperationException("Firebase sign-in for the second e2e identity did not return an id token.");
        }

        return _secondEphemeralUserIdToken;
    }

    public async ValueTask DisposeAsync()
    {
        if (End2EndConfiguration.Enabled && !End2EndConfiguration.ReadOnly)
        {
            await RemoveSeededReferenceDataAsync();
            await RemoveEphemeralUserDocumentsAsync();
        }

        _apiHttpClient?.Dispose();

        await DeleteEphemeralUserAsync(_ephemeralUserUid);
        await DeleteEphemeralUserAsync(_secondEphemeralUserUid);

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
                // best-effort cleanup of a temp file, not worth failing the run over
            }
        }
    }

    /// <summary>
    /// Shared by both ephemeral users this fixture can create (the run's own signed-in identity, and the second one <see cref="GetAnotherUsersIdTokenAsync"/> mints on demand).
    /// A failure here must never fail the run: a leftover throwaway Firebase user is untidy, not a test failure, so it is reported and swallowed the same way <see cref="RemoveSeededReferenceDataAsync"/> treats its own best-effort cleanup.
    /// </summary>
    private static async Task DeleteEphemeralUserAsync(string? uid)
    {
        if (uid is null) return;

        try
        {
            await FirebaseAuth.DefaultInstance.DeleteUserAsync(uid);
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"Failed to delete ephemeral e2e user {uid}: {ex.Message}");
        }
    }
}
