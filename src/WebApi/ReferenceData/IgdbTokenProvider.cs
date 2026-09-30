using System.Text.Json.Serialization;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Supplies the Twitch app access token every IGDB request carries, cached until shortly before it expires.
/// </summary>
public interface IIgdbTokenProvider
{
    /// <summary>The Twitch client id, sent alongside the token as IGDB's <c>Client-ID</c> header.</summary>
    string? ClientId { get; }

    /// <summary>
    /// A currently valid token, fetching one if needed. Null when IGDB isn't configured or the token request
    /// failed - callers treat that as "IGDB is unavailable", never as an exception to propagate.
    /// </summary>
    Task<string?> GetTokenAsync(CancellationToken cancellationToken = default);

    /// <summary>Drops the cached token so the next call fetches a fresh one (used when IGDB rejects it).</summary>
    void Invalidate();
}

/// <summary>
/// Fetches and caches the Twitch <c>client_credentials</c> app access token IGDB requires.
/// <para>
/// Registered as a singleton holding plain in-process state - deliberately unlike <see cref="OmdbCallBudget"/>,
/// which needs MongoDB because a *quota* is a shared fact every replica spends from. A token is not: Twitch
/// issues one per request and several remain valid at once, so each replica holding its own costs nothing and
/// coordinating them would buy nothing.
/// </para>
/// <para>
/// It resolves its HTTP client from <see cref="IHttpClientFactory"/> by name rather than taking a typed
/// <see cref="HttpClient"/>, because capturing one in a singleton pins its handler forever and defeats the
/// factory's handler rotation (the same reason the book providers are bridged with <c>AddTransient</c>).
/// A separate client from the IGDB one, since this is the call that has nothing to authenticate with yet.
/// </para>
/// </summary>
public class IgdbTokenProvider(IHttpClientFactory httpClientFactory, IgdbSettings settings, ILogger<IgdbTokenProvider> logger) : IIgdbTokenProvider
{
    /// <summary>Name of the token-endpoint <see cref="HttpClient"/> registered in Program.cs.</summary>
    public const string TokenHttpClientName = "igdb-token";

    /// <summary>
    /// How long before the stated expiry a token is renewed. Twitch app tokens last around 60 days, so this is
    /// generous by design: it only has to cover a request already in flight when the token turns over.
    /// </summary>
    private static readonly TimeSpan s_renewBefore = TimeSpan.FromHours(1);

    /// <summary>
    /// The margin actually applied, never more than half the token's own lifetime. A fixed margin longer than
    /// the lifetime would put the renewal point in the past the instant the token arrived, so every single
    /// call would fetch a new one - caching nothing while doubling the traffic to Twitch.
    /// </summary>
    private static TimeSpan RenewMargin(TimeSpan lifetime) => lifetime / 2 < s_renewBefore ? lifetime / 2 : s_renewBefore;

    private readonly SemaphoreSlim _gate = new(1, 1);

    // token and expiry travel together as one immutable record, so the fast path below reads both with a
    // single atomic reference read instead of two fields that could be seen half-updated
    private CachedToken? _cached;

    public string? ClientId => settings.ClientId;

    public async Task<string?> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        if (!settings.IsConfigured) return null;

        // the common path: a cached token, no lock, no call
        if (Volatile.Read(ref _cached) is { } cached && cached.IsUsable) return cached.Token;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            // whoever was holding the gate may already have fetched one
            if (Volatile.Read(ref _cached) is { } current && current.IsUsable) return current.Token;

            var fetched = await FetchTokenAsync(cancellationToken);
            if (fetched is null) return null;

            Volatile.Write(ref _cached, new CachedToken(fetched.Value.Token, DateTime.UtcNow + fetched.Value.Lifetime - RenewMargin(fetched.Value.Lifetime)));
            return fetched.Value.Token;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Invalidate() => Volatile.Write(ref _cached, null);

    private sealed record CachedToken(string Token, DateTime RenewAt)
    {
        public bool IsUsable => DateTime.UtcNow < RenewAt;
    }

    /// <summary>
    /// Never throws: a failed token request means IGDB is unavailable for this call, which every caller
    /// already handles, and throwing here would turn a transient Twitch outage into a 500 from an admin search.
    /// </summary>
    private async Task<(string Token, TimeSpan Lifetime)?> FetchTokenAsync(CancellationToken cancellationToken)
    {
        try
        {
            var http = httpClientFactory.CreateClient(TokenHttpClientName);
            var query = $"oauth2/token?client_id={Uri.EscapeDataString(settings.ClientId!)}" +
                        $"&client_secret={Uri.EscapeDataString(settings.ClientSecret!)}&grant_type=client_credentials";

            using var response = await http.PostAsync(query, null, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogError("Twitch rejected the IGDB token request with {StatusCode}; IGDB is unavailable until this is fixed.", response.StatusCode);
                return null;
            }

            var payload = await response.Content.ReadFromJsonAsync<TwitchTokenResponse>(cancellationToken);
            if (payload is null || string.IsNullOrEmpty(payload.AccessToken))
            {
                logger.LogError("Twitch returned no access token for IGDB.");
                return null;
            }

            return (payload.AccessToken, TimeSpan.FromSeconds(Math.Max(payload.ExpiresIn, 0)));
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogError(exception, "Fetching the IGDB access token from Twitch failed.");
            return null;
        }
    }

    private sealed class TwitchTokenResponse
    {
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        [JsonPropertyName("expires_in")]
        public long ExpiresIn { get; set; }
    }
}
