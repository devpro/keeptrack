using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Polly.CircuitBreaker;
using Polly.Timeout;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// OMDb client: looks a title up by IMDb id and returns IMDb's rating and vote count.
/// A typed <see cref="HttpClient"/> with the API key as a query parameter, like <see cref="TmdbClient"/>.
/// Without a key it does nothing, IMDb ratings being optional.
/// <para>
/// OMDb's free tier being a hard 1000 calls a day, it differs from the other clients twice.
/// Every call is first reserved against <see cref="OmdbCallBudget"/>, so no caller can bypass the quota.
/// Every failure becomes <see cref="OmdbLookupResult.NotAttempted"/>, since an exhausted key answers 401, and a throw would turn admin linking and Explore's add into 500s.
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
            // the body is read before the status, since only it tells "limit reached" from "invalid key", both 401
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

            // Response "False" for an unknown id and imdbRating "N/A" for an unrated title both mean no rating, not zero, which would sort and display as a score.
            // Both are real answers, so they count as attempted.
            if (payload is null || !string.Equals(payload.Response, "True", StringComparison.OrdinalIgnoreCase)) return OmdbLookupResult.NoRating;
            if (!TryParseRating(payload.ImdbRating, out var value)) return OmdbLookupResult.NoRating;

            return OmdbLookupResult.Rated(new OmdbRating(value, ParseVotes(payload.ImdbVotes)));
        }
        // what OMDb, the network or the resilience pipeline can raise, listed rather than caught blindly so a real bug still surfaces: connection failures, timeouts, an open circuit, and a non-JSON page from a proxy
        catch (Exception ex) when (ex is HttpRequestException or TimeoutRejectedException or BrokenCircuitException or JsonException or NotSupportedException)
        {
            logger.LogWarning(ex, "OMDb lookup failed for imdb id {ImdbId}; skipping the IMDb rating.", imdbId);
            return OmdbLookupResult.NotAttempted;
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            // a timeout of the resilience pipeline, while the caller's own cancellation propagates, or a background service shutting down would look completed
            logger.LogWarning(ex, "OMDb lookup timed out for imdb id {ImdbId}; skipping the IMDb rating.", imdbId);
            return OmdbLookupResult.NotAttempted;
        }
    }

    /// <summary>
    /// OMDb's two 401s.
    /// "Request limit reached!" is authoritative, so the shared counter is spent for the rest of the UTC day, which stops this pass's doomed calls and tells the other replicas.
    /// A rejected key cannot be retried into working either, so it stops the day the same way, logged as an error since a setting needs fixing.
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
    /// Reads the JSON body whatever the status, since OMDb answers errors in JSON too.
    /// A non-JSON body, a proxy's HTML error page, is not an OMDb answer, so it throws rather than reading as empty, and is caught with the transport failures.
    /// </summary>
    private static async Task<OmdbResponse?> ReadPayloadAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength == 0) return null;
        return await response.Content.ReadFromJsonAsync<OmdbResponse>(cancellationToken);
    }

    private static bool TryParseRating(string? rating, out double value) =>
        double.TryParse(rating, NumberStyles.Number, CultureInfo.InvariantCulture, out value) && value > 0;

    /// <summary>Parses OMDb's vote count, formatted with thousands separators ("1,950,000") or "N/A".</summary>
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
