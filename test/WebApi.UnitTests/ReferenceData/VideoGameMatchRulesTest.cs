using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// The one rule saying when a provider's candidate is the game being looked for - read by a search's ranking,
/// by automatic resolution and by provider adoption alike, so it is tested once here rather than three times
/// through its callers.
/// <para>
/// The fixtures are IGDB's real catalogue. It holds <b>eight</b> games named exactly "Resident Evil 2" (three
/// of them 1998) and seven named "Resident Evil", which is what makes the year identity in this domain rather
/// than decoration.
/// </para>
/// </summary>
[Trait("Category", "UnitTests")]
public class VideoGameMatchRulesTest
{
    private static VideoGameSearchResult Game(string id, string title, int? year) => new(id, title, year, null);

    /// <summary>Every game IGDB names exactly "Resident Evil 2", verbatim.</summary>
    private static IReadOnlyList<VideoGameSearchResult> ResidentEvil2Candidates() =>
    [
        Game("287844", "Resident Evil 2", 1999),
        Game("19686", "Resident Evil 2", 2019),
        Game("186400", "Resident Evil 2", 1998),
        Game("396728", "Resident Evil 2", 2024),
        Game("210710", "Resident Evil 2", null),
        Game("347128", "Resident Evil 2", 2025),
        Game("880", "Resident Evil 2", 1998),
        Game("217953", "Resident Evil 2", 1998)
    ];

    /// <summary>
    /// The point of asking for a year: eight candidates carry this exact title and nothing but the year says
    /// which is meant.
    /// </summary>
    [Fact]
    public void ConfirmedMatches_PicksTheOneGameFromTheRequestedYear_OutOfEightSharingTheTitle()
    {
        var matches = VideoGameMatchRules.ConfirmedMatches(ResidentEvil2Candidates(), "Resident Evil 2", 2019);

        matches.Should().ContainSingle().Which.ExternalId.Should().Be("19686");
    }

    /// <summary>
    /// An undated entry of the same name must not report an ambiguity the requested year has already settled -
    /// nothing could ever settle it, since the undated entry has no year to be told apart by. IGDB really does
    /// carry one for this title (210710).
    /// </summary>
    [Fact]
    public void ConfirmedMatches_IsNotBlockedByAnUndatedNamesake_WhenACandidateMatchesTheYearExactly()
    {
        var matches = VideoGameMatchRules.ConfirmedMatches(
            [Game("19686", "Resident Evil 2", 2019), Game("210710", "Resident Evil 2", null)], "Resident Evil 2", 2019);

        matches.Should().ContainSingle().Which.ExternalId.Should().Be("19686");
    }

    /// <summary>The year narrows, it does not invent certainty: IGDB holds three 1998 "Resident Evil 2"s.</summary>
    [Fact]
    public void ConfirmedMatches_StillReportsAnAmbiguity_WhenSeveralCandidatesShareTheRequestedYear()
    {
        var matches = VideoGameMatchRules.ConfirmedMatches(ResidentEvil2Candidates(), "Resident Evil 2", 1998);

        matches.Select(m => m.ExternalId).Should().BeEquivalentTo("186400", "880", "217953");
    }

    /// <summary>
    /// The owner's rule, reported from the running app: <b>with no year, don't match</b> - unless the search
    /// can see there is genuinely only one game by that name.
    /// <para>
    /// Several same-titled candidates from different years is exactly the state where no answer is available,
    /// so several are reported and every caller refuses. A yearless "Resident Evil 2" silently adopting the
    /// 2019 remake is the failure this pins.
    /// </para>
    /// </summary>
    [Fact]
    public void ConfirmedMatches_ConfirmsNothingUnambiguously_WhenNoYearIsSuppliedAndTheTitleIsShared()
    {
        var matches = VideoGameMatchRules.ConfirmedMatches(ResidentEvil2Candidates(), "Resident Evil 2", null);

        matches.Count.Should().BeGreaterThan(1, "nothing but the year separates these eight, and no year was given");
    }

    /// <summary>
    /// The exception that keeps the rule useful: one candidate for the title is not a guess, it is the answer.
    /// A yearless item must still resolve when the provider holds exactly one game by that name.
    /// </summary>
    [Fact]
    public void ConfirmedMatches_StillConfirms_WhenNoYearIsSuppliedButOnlyOneCandidateCarriesTheTitle()
    {
        var matches = VideoGameMatchRules.ConfirmedMatches(
            [Game("28168", "Code Vein", 2019), Game("131955", "Code Vein: Season Pass", 2019)], "Code Vein", null);

        matches.Should().ContainSingle().Which.ExternalId.Should().Be("28168");
    }

    /// <summary>Missing data is not a disagreement - a provider with no date for a game still confirms it.</summary>
    [Fact]
    public void ConfirmedMatches_AcceptsACandidateWithNoYear_WhenNothingMatchesTheYearExactly()
    {
        var matches = VideoGameMatchRules.ConfirmedMatches([Game("210710", "Resident Evil 2", null)], "Resident Evil 2", 2019);

        matches.Should().ContainSingle().Which.ExternalId.Should().Be("210710");
    }

    /// <summary>
    /// A contradicting year is never a confirmation however alone the candidate is. This is exactly where a
    /// title match is most likely to be a different game - a remake, or a same-named entry in the series.
    /// </summary>
    [Fact]
    public void ConfirmedMatches_ConfirmsNothing_WhenTheOnlyCandidatesYearContradictsTheRequest()
    {
        var matches = VideoGameMatchRules.ConfirmedMatches([Game("880", "Resident Evil 2", 1998)], "Resident Evil 2", 2019);

        matches.Should().BeEmpty();
    }

    /// <summary>A candidate that isn't this game is not rescued by sharing its release year.</summary>
    [Fact]
    public void ConfirmedMatches_ConfirmsNothing_WhenNoCandidateCarriesTheTitle()
    {
        var matches = VideoGameMatchRules.ConfirmedMatches(
            [Game("131955", "Code Vein: Season Pass", 2019), Game("119896", "Code Vein: Deluxe Edition", 2019)], "Code Vein", 2019);

        matches.Should().BeEmpty();
    }

    /// <summary>
    /// Confirmation is loose about punctuation and disambiguators but never about which work it is - the
    /// measured cases from the provider-adoption work.
    /// </summary>
    [Theory]
    [InlineData("Mass Effect: Legendary Edition", "Mass Effect Legendary Edition", true)]
    [InlineData("Disco Elysium: Final Cut", "Disco Elysium: The Final Cut", true)]
    [InlineData("GoldenEye 007 (1997)", "GoldenEye 007", true)]
    [InlineData("Assassin's Creed", "Assassins Creed", true)]
    [InlineData("Resident Evil 2", "Resident Evil 3", false)]
    [InlineData("The Sim", "The Sims", false)]
    public void ConfirmedMatches_ComparesTitlesLooselyButNeverAcrossWorks(string requested, string candidateTitle, bool confirms)
    {
        var matches = VideoGameMatchRules.ConfirmedMatches([Game("1", candidateTitle, 2019)], requested, 2019);

        matches.Should().HaveCount(confirms ? 1 : 0);
    }

    [Theory]
    [InlineData(2019, 2019, VideoGameMatchRules.YearAgrees)]
    [InlineData(null, 2019, VideoGameMatchRules.YearUnknown)]
    [InlineData(1998, 2019, VideoGameMatchRules.YearContradicts)]
    [InlineData(1998, null, VideoGameMatchRules.YearAgrees)]
    [InlineData(null, null, VideoGameMatchRules.YearAgrees)]
    public void YearRank_OrdersAgreementAboveMissingDataAboveContradiction(int? candidateYear, int? requestedYear, int expected)
    {
        VideoGameMatchRules.YearRank(candidateYear, requestedYear).Should().Be(expected);
    }
}
