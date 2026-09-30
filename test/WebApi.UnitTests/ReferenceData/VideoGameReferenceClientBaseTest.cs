using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// The search policy every video game provider shares - which queries are asked and how their answers are
/// ranked into the handful a picker shows. Tested once here against a recording fake rather than per provider,
/// the same split as <see cref="BookReferenceClientBaseTest"/>: the ordering IS the shared algorithm, and each
/// client's own job is only to build the right query.
/// <para>
/// The fixtures are the real IGDB responses that motivated this, verbatim in both content and order.
/// </para>
/// </summary>
[Trait("Category", "UnitTests")]
public class VideoGameReferenceClientBaseTest
{
    /// <summary>Records every query the policy issues, in order, and answers with whatever it was primed with.</summary>
    private sealed class RecordingVideoGameClient(
        IReadOnlyList<VideoGameSearchResult>? exactTitleResults = null,
        IReadOnlyList<VideoGameSearchResult>? relevanceResults = null) : VideoGameReferenceClientBase
    {
        public override string ProviderKey => "recording";

        public override string DisplayName => "Recording";

        public override IReadOnlyList<string> SupportedRatingSources { get; } = ["recording"];

        public List<string> Calls { get; } = [];

        protected override Task<IReadOnlyList<VideoGameSearchResult>> SearchByRelevanceAsync(string title, int limit, CancellationToken cancellationToken)
        {
            Calls.Add($"relevance:{title}@{limit}");
            return Task.FromResult(relevanceResults ?? []);
        }

        public override Task<IReadOnlyList<VideoGameSearchResult>> FindGamesByExactTitleAsync(string title, CancellationToken cancellationToken = default)
        {
            Calls.Add($"exact:{title}");
            return Task.FromResult(exactTitleResults ?? []);
        }

        public override Task<IReadOnlyList<VideoGameSearchResult>> FindGamesContainingAllWordsAsync(IReadOnlyList<string> words, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<VideoGameSearchResult>>([]);

        public override Task<VideoGameSearchResult?> FindGameByIdentifierAsync(string identifier, CancellationToken cancellationToken = default) =>
            Task.FromResult<VideoGameSearchResult?>(null);

        public override Task<VideoGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default) =>
            Task.FromResult<VideoGameDetails?>(null);

        public override Task<IReadOnlyList<VideoGameTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<VideoGameTopRatedItem>>([]);
    }

    private static VideoGameSearchResult Game(string id, string title, int? year) => new(id, title, year, null);

    /// <summary>
    /// IGDB's live answer to <c>search "Code Vein"</c>, in its own relevance order. The 2019 game the tenant is
    /// looking for is sixth - so the five results the picker used to show were its sequel, three DLC packs and
    /// a season pass, and never the game itself.
    /// </summary>
    private static IReadOnlyList<VideoGameSearchResult> CodeVeinRelevanceResults() =>
    [
        Game("347636", "Code Vein II", 2026),
        Game("131710", "Code Vein: Frozen Empress", 2020),
        Game("129134", "Code Vein: Hellfire Knight", 2020),
        Game("131954", "Code Vein: Lord of Thunder", 2020),
        Game("131955", "Code Vein: Season Pass", 2019),
        Game("28168", "Code Vein", 2019),
        Game("119896", "Code Vein: Deluxe Edition", 2019)
    ];

    /// <summary>The bug, exactly as reported: title and year both match, and the result was nowhere to be seen.</summary>
    [Fact]
    public async Task SearchGamesAsync_LeadsWithTheGameWhoseTitleAndYearBothMatch()
    {
        var client = new RecordingVideoGameClient(
            exactTitleResults: [Game("28168", "Code Vein", 2019)],
            relevanceResults: CodeVeinRelevanceResults());

        var results = await client.SearchGamesAsync("Code Vein", 2019, TestContext.Current.CancellationToken);

        results[0].ExternalId.Should().Be("28168");
    }

    /// <summary>
    /// The half that does not depend on the exact-name query answering: even when the provider only offers its
    /// relevance ranking, reading a pool deeper than the five that are displayed is what puts the match in
    /// front of the user.
    /// </summary>
    [Fact]
    public async Task SearchGamesAsync_RanksAMatchOutOfTheRelevanceOrderingAlone()
    {
        var client = new RecordingVideoGameClient(exactTitleResults: [], relevanceResults: CodeVeinRelevanceResults());

        var results = await client.SearchGamesAsync("Code Vein", 2019, TestContext.Current.CancellationToken);

        results[0].ExternalId.Should().Be("28168");
        client.Calls.Should().Equal("exact:Code Vein", "relevance:Code Vein@50");
    }

    /// <summary>
    /// A candidate that merely shares the requested year is a coincidence ("Code Vein: Season Pass" is a 2019
    /// release too); a title match is the thing being looked for. Title therefore outranks year.
    /// </summary>
    [Fact]
    public async Task SearchGamesAsync_RanksATitleMatchAboveAMereYearMatch()
    {
        var client = new RecordingVideoGameClient(relevanceResults:
        [
            Game("131955", "Code Vein: Season Pass", 2019),
            Game("28168", "Code Vein", 2019)
        ]);

        var results = await client.SearchGamesAsync("Code Vein", 2019, TestContext.Current.CancellationToken);

        results.Select(r => r.ExternalId).Should().Equal("28168", "131955");
    }

    /// <summary>
    /// What the year is actually for: IGDB holds seven games named exactly "Resident Evil", and the requested
    /// year is the only thing that says which of them the tenant means.
    /// <para>
    /// The dateless entry (102722, real) is what makes this more than a boolean: it arrives ahead of the 2002
    /// remake in IGDB's own ordering, so treating "no year" as agreement put it first for a search that plainly
    /// asked for 2002.
    /// </para>
    /// </summary>
    [Fact]
    public async Task SearchGamesAsync_UsesTheYearToSeparateGamesSharingOneName()
    {
        var client = new RecordingVideoGameClient(exactTitleResults:
        [
            Game("102722", "Resident Evil", null),
            Game("380192", "Resident Evil", 1996),
            Game("396732", "Resident Evil", 2024),
            Game("24869", "Resident Evil", 2002),
            Game("8254", "Resident Evil", 2014)
        ]);

        var results = await client.SearchGamesAsync("Resident Evil", 2002, TestContext.Current.CancellationToken);

        // the requested year first, then the entry with no year to contradict it, then the years that do
        results.Select(r => r.ExternalId).Should().Equal("24869", "102722", "380192", "396732", "8254");
    }

    /// <summary>
    /// The year narrows the order, never the result set - the "an optional narrowing parameter must never
    /// silently zero out results a broader search would find" rule. Two catalogues routinely disagree by a year
    /// over a regional or platform release, so a title match with the "wrong" year is still the best answer
    /// there is.
    /// </summary>
    [Fact]
    public async Task SearchGamesAsync_StillReportsTheTitleMatch_WhenTheProvidersYearDisagrees()
    {
        var client = new RecordingVideoGameClient(relevanceResults:
        [
            Game("131955", "Code Vein: Season Pass", 2019),
            Game("28168", "Code Vein", 2018)
        ]);

        var results = await client.SearchGamesAsync("Code Vein", 2019, TestContext.Current.CancellationToken);

        results[0].ExternalId.Should().Be("28168");
    }

    /// <summary>A year the provider simply doesn't report is missing data, not a disagreement.</summary>
    [Fact]
    public async Task SearchGamesAsync_DoesNotPenaliseACandidateWithNoYear()
    {
        var client = new RecordingVideoGameClient(relevanceResults:
        [
            Game("131955", "Code Vein: Season Pass", 2019),
            Game("28168", "Code Vein", null)
        ]);

        var results = await client.SearchGamesAsync("Code Vein", 2019, TestContext.Current.CancellationToken);

        results[0].ExternalId.Should().Be("28168");
    }

    /// <summary>
    /// Behind the match, candidates are ordered by how close they are to what was asked for rather than by the
    /// provider's relevance - which is the opinion that buried the answer at rank six to begin with. IGDB's own
    /// order for these puts the Collector's Edition first; "Elden Ring GB" is by far the nearest thing to
    /// "Elden Ring".
    /// </summary>
    [Fact]
    public async Task SearchGamesAsync_OrdersTheRestByHowCloseTheyAreToWhatWasAskedFor()
    {
        var client = new RecordingVideoGameClient(relevanceResults:
        [
            Game("180258", "Elden Ring: Collector's Edition", 2022),
            Game("296157", "Elden Ring Reforged", 2022),
            Game("119133", "Elden Ring", 2022),
            Game("206519", "Elden Ring GB", 2022)
        ]);

        var results = await client.SearchGamesAsync("Elden Ring", 2022, TestContext.Current.CancellationToken);

        results.Select(r => r.ExternalId).Should().Equal("119133", "206519", "296157", "180258");
    }

    /// <summary>
    /// The order is total - no key is ever left to the provider's relevance - so the same request twice puts
    /// the same card first. Both of these are equally far from the title asked for.
    /// </summary>
    [Fact]
    public async Task SearchGamesAsync_OrdersCandidatesTheOtherKeysCannotSeparate()
    {
        var client = new RecordingVideoGameClient(relevanceResults:
        [
            Game("131954", "Code Vein: Lord of Thunder", 2020),
            Game("129134", "Code Vein: Hellfire Knight", 2020)
        ]);

        var results = await client.SearchGamesAsync("Code Vein", 2019, TestContext.Current.CancellationToken);

        results.Select(r => r.ExternalId).Should().Equal("129134", "131954");
    }

    /// <summary>A picker's worth of candidates, out of a pool an order of magnitude deeper.</summary>
    [Fact]
    public async Task SearchGamesAsync_ReportsAtMostFiveCandidates()
    {
        var client = new RecordingVideoGameClient(
            exactTitleResults: [Game("28168", "Code Vein", 2019)],
            relevanceResults: CodeVeinRelevanceResults());

        var results = await client.SearchGamesAsync("Code Vein", 2019, TestContext.Current.CancellationToken);

        results.Should().HaveCount(5);
    }

    /// <summary>
    /// The exact-name query and the relevance search overlap by construction, and the same game must not
    /// occupy two of the five places.
    /// </summary>
    [Fact]
    public async Task SearchGamesAsync_ReportsAGameFoundByBothQueriesOnce()
    {
        var client = new RecordingVideoGameClient(
            exactTitleResults: [Game("28168", "Code Vein", 2019)],
            relevanceResults: CodeVeinRelevanceResults());

        var results = await client.SearchGamesAsync("Code Vein", 2019, TestContext.Current.CancellationToken);

        results.Select(r => r.ExternalId).Should().OnlyHaveUniqueItems();
    }

    /// <summary>With no year to rank by, a title match is still the best answer the policy can identify.</summary>
    [Fact]
    public async Task SearchGamesAsync_StillLeadsWithTheTitleMatch_WhenNoYearIsSupplied()
    {
        var client = new RecordingVideoGameClient(relevanceResults: CodeVeinRelevanceResults());

        var results = await client.SearchGamesAsync("Code Vein", null, TestContext.Current.CancellationToken);

        results[0].ExternalId.Should().Be("28168");
    }

    [Fact]
    public async Task SearchGamesAsync_AsksTheProviderNothing_WhenTheTitleIsBlank()
    {
        var client = new RecordingVideoGameClient(relevanceResults: CodeVeinRelevanceResults());

        var results = await client.SearchGamesAsync("   ", 2019, TestContext.Current.CancellationToken);

        results.Should().BeEmpty();
        client.Calls.Should().BeEmpty();
    }
}
