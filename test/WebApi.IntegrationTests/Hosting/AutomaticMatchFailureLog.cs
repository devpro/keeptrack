using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.WebApi.Filters;
using Microsoft.Extensions.Logging;

namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// Records the titles whose automatic reference match got no usable answer from its provider, read off the server's own log lines:
/// the warning each controller's <c>OnCreatedAsync</c> logs when the background match throws on the provider,
/// and the line <c>ReferenceEnrichmentService</c> logs when the provider answers no candidate at all, on creation or through "check for reference match".
/// <para>
/// The background match is fire-and-forget, and an empty answer is a normal 200, so those lines are the only trace of either:
/// a test sees the outage only as a link that never comes.
/// Asking the provider again afterwards proves nothing during a partial outage, when one search in five succeeds.
/// The tests reading this only use titles their provider holds, so an empty answer is the provider failing, never the title being unknown.
/// </para>
/// </summary>
public sealed class AutomaticMatchFailureLog : ILoggerProvider
{
    private const string FailedPrefix = "Background reference-data match failed";

    private const string NoCandidatePrefix = "Automatic reference-data match found no candidate";

    private readonly ConcurrentDictionary<string, byte> _failedTitles = new(StringComparer.Ordinal);

    public bool HasProviderFailure(string title) => _failedTitles.ContainsKey(title);

    public ILogger CreateLogger(string categoryName) => new Recorder(this);

    public void Dispose()
    {
    }

    private sealed class Recorder(AutomaticMatchFailureLog log) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (state is not IReadOnlyList<KeyValuePair<string, object?>> values) return;
            if (values.FirstOrDefault(v => v.Key == "{OriginalFormat}").Value is not string format) return;

            // a match that threw for any other reason is this application failing, which must still fail the test
            var providerFailed = format.StartsWith(FailedPrefix, StringComparison.Ordinal) && exception is not null && UpstreamFailure.Is(exception);
            if (!providerFailed && !format.StartsWith(NoCandidatePrefix, StringComparison.Ordinal)) return;

            if (values.FirstOrDefault(v => v.Key == "Title").Value is string title)
            {
                log._failedTitles.TryAdd(title, 0);
            }
        }
    }
}
