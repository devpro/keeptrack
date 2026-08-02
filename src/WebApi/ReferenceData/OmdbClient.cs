using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Polly.CircuitBreaker;
using Polly.Timeout;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// OMDb REST client - looks up a title by its IMDb id and returns IMDb's own aggregate rating/vote count.
/// Configured as a typed <see cref="HttpClient"/> (see <c>Program.cs</c>), with the api key appended as a
/// query parameter, same convention as <see cref="TmdbClient"/>/<see cref="RawgClient"/>. When no key is
/// configured the client is a graceful no-op rather than calling the provider - IMDb enrichment is optional,
/// so a deployment without an OMDb key keeps movies/TV on their TMDB rating alone.
/// <para>
/// Two things make this client different from the other providers, both because OMDb's free tier is a hard
/// 1000 calls a day. Every call is reserved against <see cref="OmdbCallBudget"/> first, so no call site can
/// bypass the quota by construction rather than by discipline. And every failure is swallowed into
/// <see cref="OmdbLookupResult.NotAttempted"/>: an exhausted key answers 401, which
/// <c>GetFromJsonAsync</c> would have thrown for - and that exception used to surface as a 500 from admin
/// manual linking and from Explore "add", both of which are supposed to treat IMDb as optional.
/// </para>
/// </summary>
public class OmdbClient(HttpClient http, OmdbSettings settings, IOmdbCallBudget budget, ILogger<OmdbClient> logger) : IOmdbClient
{
    public async Task<OmdbLookupResult> GetRatingAsync(string imdbId, OmdbCallPriority priority, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(settings.ApiKey) || string.IsNullOrEmpty(imdbId)) return OmdbLookupResult.NotAttempted;
        if (!await budget.TryReserveAsync(priority, cancellationToken)) return OmdbLookupResult.NotAttempted;

        try
        {
            using var response = await http.GetAsync($"?apikey={settings.ApiKey}&i={Uri.EscapeDataString(imdbId)}", cancellationToken);
            // read the body before checking the status: OMDb reports both "limit reached" and "invalid key"
            // as a 401 whose JSON body is the only thing that tells the two apart.
            var payload = await ReadPayloadAsync(response, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                await HandleRejectedKeyAsync(payload, cancellationToken);
                return OmdbLookupResult.NotAttempted;
            }

            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("OMDb returned {StatusCode} for imdb id {ImdbId}; skipping the IMDb rating.", (int)response.StatusCode, imdbId);
                return OmdbLookupResult.NotAttempted;
            }

            // OMDb returns Response:"False" for an unknown id, and imdbRating:"N/A" for a title nobody has rated -
            // both are "no rating", not a genuine zero (a stored 0 would sort as a real score and render a "0" pill).
            // Both are genuine answers, though, so they count as attempted.
            if (payload is null || !string.Equals(payload.Response, "True", StringComparison.OrdinalIgnoreCase)) return OmdbLookupResult.NoRating;
            if (!TryParseRating(payload.ImdbRating, out var value)) return OmdbLookupResult.NoRating;

            return OmdbLookupResult.Rated(new OmdbRating(value, ParseVotes(payload.ImdbVotes)));
        }
        // everything OMDb, the network, or the resilience pipeline can raise - enumerated rather than a blanket
        // catch, so a genuine bug in this method still surfaces instead of being reported as "no rating":
        // HttpRequestException (connection/DNS/TLS), TimeoutRejectedException + TaskCanceledException (the
        // per-attempt and total timeouts), BrokenCircuitException (the breaker open after repeated failures),
        // JsonException/NotSupportedException (a non-JSON error page from a proxy in front of OMDb).
        catch (Exception ex) when (ex is HttpRequestException or TimeoutRejectedException or BrokenCircuitException or JsonException or NotSupportedException)
        {
            logger.LogWarning(ex, "OMDb lookup failed for imdb id {ImdbId}; skipping the IMDb rating.", imdbId);
            return OmdbLookupResult.NotAttempted;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // a timeout from the resilience pipeline, not the caller giving up - the caller's own cancellation
            // must keep propagating, or a shutting-down background service would look like it completed
            logger.LogWarning("OMDb lookup timed out for imdb id {ImdbId}; skipping the IMDb rating.", imdbId);
            return OmdbLookupResult.NotAttempted;
        }
    }

    /// <summary>
    /// OMDb's two 401s. "Request limit reached!" is the one the budget exists for - it's authoritative, so the
    /// shared counter is written off for the rest of the UTC day, which is both what stops this pass from
    /// firing hundreds of doomed calls and what tells the other replicas. A rejected/absent key can't be
    /// retried into working either, so it stops the day the same way rather than failing once per item; it's
    /// logged as an error because, unlike a spent quota, it needs someone to fix a setting.
    /// </summary>
    private async Task HandleRejectedKeyAsync(OmdbResponse? payload, CancellationToken cancellationToken)
    {
        var error = payload?.Error ?? "no error message";
        if (error.Contains("limit", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning("OMDb daily request limit reached ({Error}); IMDb lookups stop until the next UTC day.", error);
        }
        else
        {
            logger.LogError("OMDb rejected the configured API key ({Error}); IMDb lookups are disabled until the next UTC day.", error);
        }

        await budget.MarkLimitReachedAsync(cancellationToken);
    }

    /// <summary>
    /// Reads the JSON body whatever the status code - OMDb answers its errors in JSON too. A body that isn't
    /// JSON at all (a proxy's HTML error page) is not an OMDb answer, so it raises rather than being read as
    /// an empty one, and is caught with the other transport failures.
    /// </summary>
    private static async Task<OmdbResponse?> ReadPayloadAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength == 0) return null;
        return await response.Content.ReadFromJsonAsync<OmdbResponse>(cancellationToken);
    }

    private static bool TryParseRating(string? rating, out double value) =>
        double.TryParse(rating, NumberStyles.Number, CultureInfo.InvariantCulture, out value) && value > 0;

    /// <summary>OMDb formats vote counts with thousands separators ("1,950,000") or "N/A" - strip and parse.</summary>
    private static int? ParseVotes(string? votes) =>
        int.TryParse(votes, NumberStyles.Number, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

    private sealed class OmdbResponse
    {
        [JsonPropertyName("imdbRating")]
        public string? ImdbRating { get; set; }

        [JsonPropertyName("imdbVotes")]
        public string? ImdbVotes { get; set; }

        [JsonPropertyName("Response")]
        public string? Response { get; set; }

        /// <summary>OMDb's own error text ("Request limit reached!", "Invalid API key!", "Incorrect IMDb ID.").</summary>
        [JsonPropertyName("Error")]
        public string? Error { get; set; }
    }
}
