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
    /// A valid token, fetched if needed.
    /// Null when IGDB is not configured or the request failed, which callers treat as IGDB being unavailable.
    /// </summary>
    Task<string?> GetTokenAsync(CancellationToken cancellationToken = default);

    /// <summary>Drops the cached token, when IGDB rejects it, so the next call fetches a fresh one.</summary>
    void Invalidate();
}

/// <summary>
/// Fetches and caches the Twitch <c>client_credentials</c> app access token IGDB requires.
/// <para>
/// A singleton with state in the process, unlike <see cref="OmdbCallBudget"/>, whose quota is shared by every replica.
/// Twitch issues a token per request and several stay valid, so each replica holding its own costs nothing.
/// </para>
/// <para>
/// It resolves a named client from <see cref="IHttpClientFactory"/>, since a typed <see cref="HttpClient"/> captured in a singleton would pin its handler and defeat rotation.
/// That client is apart from IGDB's, having nothing to authenticate with yet.
/// </para>
/// </summary>
public class IgdbTokenProvider(IHttpClientFactory httpClientFactory, IgdbSettings settings, ILogger<IgdbTokenProvider> logger) : IIgdbTokenProvider
{
    /// <summary>Name of the token endpoint's <see cref="HttpClient"/>, registered in Program.cs.</summary>
    public const string TokenHttpClientName = "igdb-token";

    /// <summary>
    /// How long before its expiry a token is renewed, generous since a Twitch app token lasts about 60 days, and only a request in flight at the turnover needs covering.
    /// </summary>
    private static readonly TimeSpan s_renewBefore = TimeSpan.FromHours(1);

    /// <summary>
    /// The margin applied, never more than half the token's lifetime.
    /// A margin longer than the lifetime would place the renewal in the past as the token arrives, so every call would fetch a new one.
    /// </summary>
    private static TimeSpan RenewMargin(TimeSpan lifetime) => lifetime / 2 < s_renewBefore ? lifetime / 2 : s_renewBefore;

    private readonly SemaphoreSlim _gate = new(1, 1);

    // token and expiry travel as one immutable record, read atomically, rather than two fields seen half updated
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
            // the previous holder of the gate may have fetched one
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
    /// Never throws: a failed request makes IGDB unavailable for this call, which callers handle, where a throw would turn a Twitch outage into a 500.
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
