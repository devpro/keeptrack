using Microsoft.Extensions.Http.Resilience;

namespace Keeptrack.WebApi.DependencyInjection;

internal static class ProviderResilienceExtensions
{
    /// <summary>
    /// The one resilience pipeline every external reference provider client (TMDB/RAWG/Open
    /// Library/Discogs) gets: the standard handler (retry, per-attempt timeout, total timeout, circuit
    /// breaker) with the per-attempt bound pinned explicitly to 10 seconds. That is the handler's own
    /// default today, made explicit so a package upgrade can never silently change the contract: a stuck
    /// provider call is abandoned after 10s and retried, never left hanging. Pair with
    /// <c>client.Timeout = Timeout.InfiniteTimeSpan</c> on the HttpClient itself (see Program.cs's
    /// comment on why HttpClient's own 100s timeout must not compete with this pipeline).
    /// </summary>
    internal static void AddProviderResilienceHandler(this IHttpClientBuilder builder) =>
        builder.AddStandardResilienceHandler(options => options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(10));

    /// <summary>
    /// Same pipeline as <see cref="AddProviderResilienceHandler"/>, with a larger retry budget - confirmed
    /// against the real API that Google Books returns a transient 500/503 noticeably more often than
    /// TMDB/RAWG/Discogs, and 3 retries (the shared default) isn't always enough to ride it out.
    /// Applied to all three book providers (not just Google Books) for consistency, since Open Library/BnF
    /// share the same registry/fallback shape and there's no reason to special-case just one of the three.
    /// The retry delay is shortened (1s base instead of the default 2s) so the extra attempts still fit
    /// comfortably under the widened total budget instead of mostly being eaten by exponential backoff.
    /// </summary>
    internal static void AddBookProviderResilienceHandler(this IHttpClientBuilder builder) =>
        builder.AddStandardResilienceHandler(options =>
        {
            options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(10);
            options.Retry.MaxRetryAttempts = 5;
            options.Retry.Delay = TimeSpan.FromSeconds(1);
            options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(40);
        });
}
