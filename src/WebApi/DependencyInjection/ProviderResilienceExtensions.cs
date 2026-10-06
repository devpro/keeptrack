using Microsoft.Extensions.Http.Resilience;

namespace Keeptrack.WebApi.DependencyInjection;

internal static class ProviderResilienceExtensions
{
    /// <summary>
    /// The resilience pipeline of every provider client:
    /// the standard handler (retry, per-attempt timeout, total timeout, circuit breaker) with the per-attempt bound pinned to 10 seconds.
    /// That is the handler's default, made explicit so a package upgrade never silently changes it: a stuck call is abandoned after 10s and retried, never left hanging.
    /// Paired with <c>client.Timeout = Timeout.InfiniteTimeSpan</c> (see Program.cs for why HttpClient's own 100s timeout must not compete).
    /// </summary>
    /// <remarks>
    /// Returns the builder for chaining, since a handler added after this call runs inside the pipeline (see the IGDB rate limiter in Program.cs).
    /// </remarks>
    internal static IHttpClientBuilder AddProviderResilienceHandler(this IHttpClientBuilder builder)
    {
        builder.AddStandardResilienceHandler(options => options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(10));
        return builder;
    }

    /// <summary>
    /// <see cref="AddProviderResilienceHandler"/> with a larger retry budget,
    /// since Google Books returns a transient 500 or 503 more often than the other providers, and the default 3 retries are not always enough.
    /// All three book providers get it, since they share one registry and fallback shape.
    /// The retry delay base is 1s rather than 2s, so the extra attempts fit the wider total budget rather than going to exponential backoff.
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
