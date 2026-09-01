namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// The same host with every third-party provider credential blanked, for the test classes that start a real
/// <c>sync-now</c> job.
/// <para>
/// Those tests assert an HTTP contract - 202 with a job id, a queryable status, the Explore-only variant not
/// walking the reference stages - but the job they start is the real pass, and it runs on against the live
/// providers long after the test has finished. That had three costs, all invisible from the tests themselves:
/// it rewrote the shared <c>explore_catalogue</c> ranking with real TMDB data (documents no cleanup can
/// register at creation time, because the pass writes them minutes after the test ends - 39 of them were found
/// in the test database, and they broke <c>ExploreSmokeTest</c>, whose premise is that a seeded ranking is the
/// whole ranking); it mutated shared reference documents; and it spent OMDb calls from a real 1000/day budget
/// on every single run.
/// </para>
/// <para>
/// With no credentials, each provider call short-circuits or fails and is caught per document, so the job still
/// starts, still reports its stages, and still ends - which is all these tests look at - while writing nothing.
/// The same principle the e2e suite already runs on ("hosted mode simply provides no provider keys, so no
/// external network flakiness enters the suite"), applied to the one place in this suite that was still
/// reaching outside on every run. A test that genuinely wants the live pass
/// (<c>ReferenceSyncPollingResourceTest</c>, opt-in) keeps the ordinary host.
/// </para>
/// </summary>
public sealed class ProviderlessWebAppFactory() : KestrelWebAppFactory<Program>(
[
    new("Tmdb:ApiKey", ""),
    new("Rawg:ApiKey", ""),
    new("Igdb:ClientId", ""),
    new("Igdb:ClientSecret", ""),
    new("Discogs:Token", ""),
    new("GoogleBooks:ApiKey", ""),
    new("Omdb:ApiKey", "")
]);
