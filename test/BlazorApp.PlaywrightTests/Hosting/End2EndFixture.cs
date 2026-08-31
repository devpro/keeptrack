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
/// Assembly-wide setup for the whole e2e run (xunit v3 <c>[assembly: AssemblyFixture(typeof(End2EndFixture))]</c>):
/// resolves the run mode, hosts both apps in-process (or targets a live deployment), signs in exactly once, and seeds deterministic reference data.
/// Every smoke test class takes this as a constructor parameter and reuses the single instance -
/// critically, this means the whole run performs at most one real Firebase sign-in and one ephemeral-user creation, not one per test class.
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
    /// The email of the single signed-in identity for the run - the ephemeral user's generated address in
    /// integration mode, or the configured E2E_USERNAME otherwise. The sharing smoke test self-shares to this
    /// address (the recipient is matched by email server-side), the same way ShareResourceTest uses
    /// FirebaseConfiguration.Username.
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
            // Self-hosted mode runs the real WebApi against a real MongoDB, so the same guard the integration
            // suite applies belongs here too - without it an unset Infrastructure__MongoDB__DatabaseName silently
            // points the whole e2e run at the developer's own keeptrack_dev database. Live mode is exempt: the
            // deployment owns its own configuration and there's no local database to mis-target.
            // The name checked is the one this run will actually use, which is E2E_MONGODB_DATABASE's, not the
            // ambient variable's (see End2EndConfiguration.DatabaseName for why this suite picks its own).
            TestDatabaseGuard.EnsureTestDatabaseName(End2EndConfiguration.DatabaseName);

            _webApiFactory = new KestrelWebAppFactory<Keeptrack.WebApi.Program>(
                WebApiKestrelUrlOverride,
                new KeyValuePair<string, string?>("Features:IsReferenceSyncEnabled", "false"),
                new KeyValuePair<string, string?>("Infrastructure:MongoDB:DatabaseName", End2EndConfiguration.DatabaseName),
                // Pinned to igdb rather than inherited from appsettings.Development.json, so the suite doesn't
                // drift with an unrelated deployment choice: IGDB is the more stable provider and is what
                // VideoGameReferenceMatchSmokeTest is written against (it hard-requires Igdb__ClientId/
                // Igdb__ClientSecret but deliberately not Rawg__ApiKey).
                new KeyValuePair<string, string?>("ReferenceData:VideoGameProvider", "igdb"));
            _webApiBaseUrl = _webApiFactory.ServerAddress;

            // The hosted Blazor app needs WebApi:BaseUrl injected with the WebApi host's own dynamic address -
            // but BlazorApp's Program.cs reads it via builder.Configuration.TryGetSection(...) *before* WebApplicationBuilder.Build() runs,
            // which is earlier than WebApplicationFactory's own ConfigureWebHost/ConfigureAppConfiguration override can reach
            // (that override only affects the configuration used *after* Build()).
            // Confirmed against a real run: passing this the same way as the WebApi factory's Features:IsReferenceSyncEnabled override below left the Blazor host
            // silently dialing its static appsettings.Development.json WebApi:BaseUrl instead.
            // A real process environment variable is read synchronously by WebApplication.CreateBuilder itself, so it's visible in time.
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
    /// Movie/TvShow/VideoGame/Album smoke tests link real, well-known titles against the real providers (Book/Open Library needs no key) -
    /// fail fast with a clear error rather than letting those tests fail downstream with a confusing "no results found".
    /// Only checked in self-hosted integration mode, since a live deployment's configuration can't be inspected this way -
    /// live mode trusts the deployment is already configured correctly.
    /// </summary>
    private void EnsureReferenceProviderKeysConfigured()
    {
        var configuration = _webApiFactory!.Services.GetRequiredService<IConfiguration>();
        // the video game entry is IGDB's Twitch pair, not RAWG's key: what a smoke test links through is
        // whichever provider is the *default*, and RAWG stopped being it. RAWG is still registered (references
        // linked through it keep their stored ratings), but no e2e path reaches it unless a test picks it explicitly, so
        // requiring its key would fail runs for a provider they never call.
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
    /// An explicit E2E_USERNAME always wins (works in every mode). Otherwise, integration mode creates its own ephemeral admin user -
    /// live mode and read-only mode both require an explicit account, since neither creates or cleans up a throwaway Firebase user.
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

        // The Blazor host (already started above) initialized FirebaseApp.DefaultInstance from its own Firebase:ServiceAccount configuration (see src/BlazorApp/Program.cs) -
        // reused here rather than parsing the service account credential a second time.
        var email = $"e2e-{Guid.NewGuid():N}@keeptrack.test";
        var password2 = $"E2e-{Guid.NewGuid():N}!Aa1";
        var user = await FirebaseAuth.DefaultInstance.CreateUserAsync(new UserRecordArgs { Email = email, Password = password2, EmailVerified = true });
        await FirebaseAuth.DefaultInstance.SetCustomUserClaimsAsync(user.Uid, new Dictionary<string, object> { ["role"] = "admin" });
        _ephemeralUserUid = user.Uid;
        return (email, password2);
    }

    /// <summary>
    /// Programmatic sign-in: the login page is OAuth-popup-only and cannot be automated (see the e2e plan),
    /// but <c>POST /auth/callback</c> accepts any verified Firebase ID token.
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
    /// The deterministic "look for a ref" path: import a synthetic reference document via the same admin endpoint a real export/import round-trip uses,
    /// so <c>ReferenceSmokeTest</c>'s "check for reference match" click only ever queries MongoDB, never a real provider.
    /// <para>
    /// Re-seeding is a no-op rather than a 23rd copy of the same synthetic book (22 identical "The Playwright Chronicles" documents had once piled up in a real test database):
    /// the import matches on the fixture's Open Library id, so it updates whatever document already carries it - see <c>ReferenceDataImportService</c>.
    /// The fixed <see cref="ReferenceFixtureZipBuilder.ReferenceId"/> is what the *first* insert lands under, which is how <see cref="RemoveSeededReferenceDataAsync"/> knows what to delete afterwards.
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
    /// Goes through the hosted <see cref="IBookReferenceRepository"/> rather than an HTTP call, because there is no admin endpoint that deletes a single reference document
    /// (the only such path is a tenant item's own <c>unlink-reference</c>, which needs a linked item to unlink) - and inventing a delete endpoint just to let tests tidy up would be the wrong trade.
    /// This is only possible in self-hosted mode; in live mode the import's provider-id matching already makes re-seeding a replace rather than an insert, so nothing accumulates there either.
    /// </para>
    /// Best-effort and never fatal: the run's results are already in, and a teardown error shouldn't turn a green run red.
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
    /// Removes the documents the run's throwaway identity owns that no test can reach: its preferences (written the first time a page reads them)
    /// and its background-job rows (an import smoke test starts a job through the UI and never learns its id).
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
    /// A test proving that matching reaches the <b>provider</b> can only observe that while nothing local answers - and it creates exactly such a local answer by passing.
    /// Left behind, it makes its own next run take the cheap local path instead, still green and no longer testing anything.
    /// Confirmed by mutation: with the provider escalation disabled, the three video game matching scenarios all still passed against a database holding last run's references.
    /// </para>
    /// <para>
    /// Self-hosted mode only, and silent when it cannot run - see <see cref="CanSeedDatabaseDirectly"/>.
    /// </para>
    /// </remarks>
    public Task RemoveVideoGameReferencesAsync(IEnumerable<string> referenceIds) =>
        RemoveReferencesAsync("videogame_reference", referenceIds);

    /// <summary>
    /// The same removal for any reference collection - the four other domains now have matching journeys of
    /// their own, and their references have to go for exactly the reason this one's do.
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
    /// Whether this run may write to MongoDB directly, i.e. self-hosted mode - live mode (<c>E2E_TARGET_URL</c>)
    /// drives a remote deployment whose database this process has no handle on.
    /// Only the Explore catalogue needs it (see <see cref="SeedExploreCatalogueAsync"/>); a test that does
    /// self-skips when it is false.
    /// </summary>
    public bool CanSeedDatabaseDirectly => _webApiFactory is not null;

    /// <summary>
    /// Writes entries into the shared, owner-less <c>explore_catalogue</c> so the Explore page has a
    /// deterministic ranking to render.
    /// <para>
    /// Straight through the hosted <see cref="IExploreCatalogueRepository"/>, unlike the reference seed above
    /// which goes over HTTP: the catalogue is only ever written by <c>ExploreCatalogueRefreshService</c>, which
    /// this host deliberately never runs (<c>Features:IsReferenceSyncEnabled</c> is false) and which would call
    /// the real TMDB/RAWG rankings if it did. There is no admin endpoint that writes one entry, and inventing
    /// one just so tests can seed would be the wrong trade - the same reasoning as
    /// <see cref="RemoveSeededReferenceDataAsync"/> going straight to a repository to delete.
    /// </para>
    /// <para>
    /// That the sync never runs here is also what makes low ranks safe to seed at: nothing else ever puts an
    /// entry in this collection, so a seeded ranking is the whole ranking and the page's first fetch shows it.
    /// </para>
    /// </summary>
    public async Task SeedExploreCatalogueAsync(IReadOnlyList<ExploreCatalogueEntryModel> entries)
    {
        using var scope = _webApiFactory!.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<IExploreCatalogueRepository>().UpsertManyAsync(entries);
    }

    /// <summary>
    /// Every ordering a domain's catalogue is maintained under, asked of the hosted app rather than hardcoded -
    /// a seeded entry filed under any other ranking key is invisible to the page. Resolved from the API's own
    /// container because the answer depends on which provider that deployment has registered as the domain's
    /// discovery provider (movies/TV have one ordering, video games one per rating source IGDB supports).
    /// <para>
    /// All of them, not just the effective one: which ordering the page reads follows the admin-selected
    /// primary rating source, a stored setting no test controls, so a seed that guessed at it would break on a
    /// database where someone had picked the other one.
    /// </para>
    /// </summary>
    public IReadOnlyList<string> ExploreRankingsFor(ExploreItemType type)
    {
        using var scope = _webApiFactory!.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<ExploreRankings>().Rankings(type);
    }

    /// <summary>
    /// How many entries the shared catalogue already holds - the premise every Explore smoke test rests on
    /// (see <see cref="SeedExploreCatalogueAsync"/>: a seeded ranking is meant to be the whole ranking).
    /// It stops being true the moment this run shares its database with a suite whose <c>sync-now</c> tests
    /// rebuild the real TMDB ranking, and the symptom is a card count nobody can explain.
    /// </summary>
    public async Task<long> CountExploreCatalogueEntriesAsync()
    {
        var database = _webApiFactory!.Services.GetRequiredService<IMongoDatabase>();
        return await database.GetCollection<BsonDocument>("explore_catalogue")
            .CountDocumentsAsync(Builders<BsonDocument>.Filter.Empty);
    }

    /// <summary>
    /// Removes seeded catalogue entries by their provider ids. The repository only exposes the refresh pass's
    /// own "delete what I didn't rewrite" sweep, which would take the whole ranking with it, so this deletes
    /// exactly what the test created and nothing else.
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
    /// <see cref="End2EndFixture"/> is a single instance shared by every parallel-running smoke test class,
    /// and several of them call <see cref="DeleteItemAsync"/> from their own cleanup -
    /// a plain <c>??=</c> lazy-init here is not thread-safe against that, confirmed by a real intermittent failure under a full parallel run.
    /// <see cref="LazyInitializer.EnsureInitialized{T}(ref T?, Func{T})"/> is the same thread-safe pattern <c>Testing.Shared</c>'s own <c>AccountRepository.AuthenticateAsync</c>
    /// already uses for exactly this kind of shared, lazily-created, concurrently-accessed resource.
    /// Public so a test that needs direct, signed-in API access beyond <see cref="DeleteItemAsync"/> (e.g. <c>MobileScreenshotTest</c>'s seeding)
    /// reuses the run's one authenticated identity instead of re-deriving credentials itself -
    /// which would silently break in ephemeral-user mode, where no E2E_USERNAME exists to re-derive from.
    /// </summary>
    public HttpClient ApiHttpClient => LazyInitializer.EnsureInitialized(ref _apiHttpClient, () =>
    {
        var client = new HttpClient { BaseAddress = new Uri(_webApiBaseUrl) };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _idToken);
        return client;
    });

    /// <summary>
    /// Deletes an item directly via the API rather than through the UI -
    /// meant to be called from a smoke test's own <c>finally</c> block, so a mid-test assertion failure still cleans up.
    /// This matters more here than it did for Book's phase-2 tests: Movie/TvShow/VideoGame/Album smoke tests use fixed,
    /// recognizable real-world titles (not a random GUID) so the reference-provider search means something,
    /// which makes an orphaned leftover from a failed run an actual accumulating duplicate, not just harmless clutter with a never-repeated name.
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
    /// Reads the ids of the items returned by a paged list query (e.g. <c>"/api/books?search=..."</c> or <c>"/api/episodes?TvShowId=..."</c>),
    /// so an import smoke test can find whatever the commit created and delete it via <see cref="DeleteItemAsync"/>.
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
    /// Forges a Blazor auth cookie whose principal is a fully-authorized member but whose stored Firebase token
    /// is a value WebApi rejects (a malformed JWT), reproducing a live session whose Firebase ID token has gone
    /// stale (expired or revoked) while the 8h auth cookie is still valid. The next server-rendered page's API
    /// call then comes back 401, driving <c>AuthenticationTokenHandler.RedirectToLogin</c> during the
    /// SSR/prerender pass - the path that used to throw "RemoteNavigationManager has not been initialized",
    /// showing a red error until the user manually refreshed.
    /// Returns <c>null</c> in live mode (E2E_TARGET_URL): forging the ticket needs the in-process Blazor host's
    /// own data-protection keys, which a remote deployment can't expose - the test self-skips there.
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
            // admin satisfies the MemberOnly policy the shared-collection page requires, so the page renders and
            // makes its API call rather than being bounced by [Authorize] first (which would exercise the wrong
            // redirect path - the cookie-challenge one, not the stale-token one under test).
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
    /// A second, genuinely different Firebase identity's valid ID token, for the one test that proves
    /// <c>AuthenticationController.Refresh</c> refuses a token that verifies but belongs to someone else's
    /// session.
    /// Created once per run on first call and reused, the same lazy-and-cached shape as
    /// <see cref="ApiHttpClient"/>.
    /// Returns <c>null</c> for the same reason <see cref="ForgeStaleTokenMemberCookie"/> does: minting a
    /// user needs the in-process Blazor host's own Firebase Admin SDK access, which live and read-only
    /// mode don't have.
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
                // best-effort cleanup of a temp file - not worth failing the run over.
            }
        }
    }

    /// <summary>
    /// Shared by both ephemeral users this fixture can create (the run's own signed-in identity, and the
    /// second one <see cref="GetAnotherUsersIdTokenAsync"/> mints on demand).
    /// A failure here must never fail the run: a leftover throwaway Firebase user is untidy, not a test
    /// failure, so it is reported and swallowed the same way <see cref="RemoveSeededReferenceDataAsync"/>
    /// treats its own best-effort cleanup.
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
