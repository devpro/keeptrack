namespace Keeptrack.WebApi.IntegrationTests.Hosting;

/// <summary>
/// The same host with every third-party provider credential blanked, for the test classes that start a real <c>sync-now</c> job.
/// <para>
/// Those tests assert an HTTP contract (202 with a job id, a queryable status, the Explore-only variant skipping the reference stages), but the job they start is the real pass, running on after the test.
/// Against live providers it would rewrite the shared <c>explore_catalogue</c> with real TMDB data minutes after the test, which no cleanup can register, and which breaks <c>ExploreSmokeTest</c>'s premise.
/// It would also mutate shared reference documents and spend OMDb calls from a real 1000/day budget on every run.
/// </para>
/// <para>
/// With no credentials, each provider call short-circuits or fails and is caught per document, so the job still starts, reports its stages and ends, all these tests look at, while writing nothing.
/// The e2e suite's hosted mode runs on the same principle, providing no provider keys.
/// A test that genuinely wants the live pass (<c>ReferenceSyncPollingResourceTest</c>, opt-in) keeps the ordinary host.
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
