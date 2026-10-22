using Polly.CircuitBreaker;
using Polly.Timeout;

namespace Keeptrack.WebApi.Filters;

/// <summary>
/// Tells a provider failing from this application failing.
/// <para>
/// The integration tests ask the same question of a background match, which has no HTTP answer to read a 502 from,
/// so the two can't drift apart on what counts as an outage.
/// </para>
/// </summary>
public static class UpstreamFailure
{
    /// <summary>
    /// A provider that timed out, exhausted its retries or tripped its circuit breaker.
    /// The only outbound HTTP the API makes is to those providers, so any <see cref="HttpRequestException"/> is theirs.
    /// </summary>
    public static bool Is(Exception exception) =>
        exception is TimeoutRejectedException or BrokenCircuitException or HttpRequestException;
}
