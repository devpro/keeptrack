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
}
