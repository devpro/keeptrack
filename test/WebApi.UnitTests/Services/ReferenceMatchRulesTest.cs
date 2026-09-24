using System.Collections.Generic;
using System.Linq;
using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// The one rule saying when a provider's candidate is the work being looked for - read by every domain's
/// search ranking, by automatic resolution and by video game provider adoption alike, so it is tested once
/// here rather than once per caller.
/// <para>
/// The fixtures are the providers' real catalogues. IGDB holds <b>eight</b> games named exactly
/// "Resident Evil 2" (three of them 1998) and seven named "Resident Evil", which is what makes the year the
/// identity in that domain rather than decoration; Google Books holds 300 volumes of "The Hobbit", which is
/// what makes the year useless in the other.
/// </para>
/// </summary>
[Trait("Category", "UnitTests")]
public class ReferenceMatchRulesTest
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
        var matches = ReferenceMatchRules.ConfirmedMatches(ResidentEvil2Candidates(), "Resident Evil 2", 2019);

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
        var matches = ReferenceMatchRules.ConfirmedMatches(
            [Game("19686", "Resident Evil 2", 2019), Game("210710", "Resident Evil 2", null)], "Resident Evil 2", 2019);

        matches.Should().ContainSingle().Which.ExternalId.Should().Be("19686");
    }

    /// <summary>The year narrows, it does not invent certainty: IGDB holds three 1998 "Resident Evil 2"s.</summary>
    [Fact]
    public void ConfirmedMatches_StillReportsAnAmbiguity_WhenSeveralCandidatesShareTheRequestedYear()
    {
        var matches = ReferenceMatchRules.ConfirmedMatches(ResidentEvil2Candidates(), "Resident Evil 2", 1998);

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
        var matches = ReferenceMatchRules.ConfirmedMatches(ResidentEvil2Candidates(), "Resident Evil 2", null);

        matches.Count.Should().BeGreaterThan(1, "nothing but the year separates these eight, and no year was given");
    }

    /// <summary>
    /// The exception that keeps the rule useful: one candidate for the title is not a guess, it is the answer.
    /// A yearless item must still resolve when the provider holds exactly one game by that name.
    /// </summary>
    [Fact]
    public void ConfirmedMatches_StillConfirms_WhenNoYearIsSuppliedButOnlyOneCandidateCarriesTheTitle()
    {
        var matches = ReferenceMatchRules.ConfirmedMatches(
            [Game("28168", "Code Vein", 2019), Game("131955", "Code Vein: Season Pass", 2019)], "Code Vein", null);

        matches.Should().ContainSingle().Which.ExternalId.Should().Be("28168");
    }

    /// <summary>Missing data is not a disagreement - a provider with no date for a game still confirms it.</summary>
    [Fact]
    public void ConfirmedMatches_AcceptsACandidateWithNoYear_WhenNothingMatchesTheYearExactly()
    {
        var matches = ReferenceMatchRules.ConfirmedMatches([Game("210710", "Resident Evil 2", null)], "Resident Evil 2", 2019);

        matches.Should().ContainSingle().Which.ExternalId.Should().Be("210710");
    }

    /// <summary>
    /// A contradicting year is never a confirmation however alone the candidate is. This is exactly where a
    /// title match is most likely to be a different game - a remake, or a same-named entry in the series.
    /// </summary>
    [Fact]
    public void ConfirmedMatches_ConfirmsNothing_WhenTheOnlyCandidatesYearContradictsTheRequest()
    {
        var matches = ReferenceMatchRules.ConfirmedMatches([Game("880", "Resident Evil 2", 1998)], "Resident Evil 2", 2019);

        matches.Should().BeEmpty();
    }

    /// <summary>A candidate that isn't this game is not rescued by sharing its release year.</summary>
    [Fact]
    public void ConfirmedMatches_ConfirmsNothing_WhenNoCandidateCarriesTheTitle()
    {
        var matches = ReferenceMatchRules.ConfirmedMatches(
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
        var matches = ReferenceMatchRules.ConfirmedMatches([Game("1", candidateTitle, 2019)], requested, 2019);

        matches.Should().HaveCount(confirms ? 1 : 0);
    }

    [Theory]
    [InlineData(2019, 2019, ReferenceMatchRules.YearAgrees)]
    [InlineData(null, 2019, ReferenceMatchRules.YearUnknown)]
    [InlineData(1998, 2019, ReferenceMatchRules.YearContradicts)]
    [InlineData(1998, null, ReferenceMatchRules.YearAgrees)]
    [InlineData(null, null, ReferenceMatchRules.YearAgrees)]
    public void YearRank_OrdersAgreementAboveMissingDataAboveContradiction(int? candidateYear, int? requestedYear, int expected)
    {
        ReferenceMatchRules.YearRank(candidateYear, requestedYear).Should().Be(expected);
    }

    private static BookSearchResult Book(string id, string title, int? year, string? author) => new(id, title, year, author, null);

    /// <summary>
    /// The whole reason books need their own shape. Google Books answers "The Hobbit" by Tolkien with 300
    /// volumes; treating that as an ambiguity is what left every book in the catalogue unlinkable, so the
    /// printings confirm together and the closest one leads.
    /// <para>
    /// The "(Enhanced Edition)" volume is set aside rather than confirmed, because two candidates are spelled
    /// exactly what was asked for and an exact spelling always beats a loose one - the same tier that keeps
    /// <i>Alien</i> and <i>The Alien</i> apart. It costs nothing here: it is the same work either way, and only
    /// the first match is ever linked.
    /// </para>
    /// </summary>
    [Fact]
    public void ConfirmedCreatorMatches_TreatsPrintingsOfOneWorkAsMatches_RatherThanAsAnAmbiguity()
    {
        var matches = ReferenceMatchRules.ConfirmedCreatorMatches(
            [
                Book("a", "The Hobbit", 1981, "John Ronald Reuel Tolkien"),
                Book("b", "The Hobbit", 2012, "J.R.R. Tolkien"),
                Book("c", "The Hobbit (Enhanced Edition)", 2011, "J. R. R. Tolkien")
            ],
            "The Hobbit", "Tolkien");

        matches.Select(m => m.ExternalId).Should().BeEquivalentTo(["a", "b"], "two printings of one book are not two books");
    }

    /// <summary>
    /// The three spellings Google Books credits one author under must not read as three authors. Requiring the
    /// candidates to agree with <i>each other</i> about the creator would refuse the very case this exists for;
    /// they only have to agree with what the tenant supplied.
    /// </summary>
    [Fact]
    public void ConfirmedCreatorMatches_AcceptsOneAuthorSpelledSeveralWays()
    {
        ReferenceMatchRules.CreatorMatches("J.R.R. Tolkien", "Tolkien").Should().BeTrue();
        ReferenceMatchRules.CreatorMatches("John Ronald Reuel Tolkien", "Tolkien").Should().BeTrue();
        ReferenceMatchRules.CreatorMatches("Tolkien", "J. R. R. Tolkien").Should().BeTrue();
    }

    /// <summary>A different author is still a different book, however exactly the title matches.</summary>
    [Fact]
    public void ConfirmedCreatorMatches_RefusesTheRightTitleByTheWrongAuthor()
    {
        var matches = ReferenceMatchRules.ConfirmedCreatorMatches(
            [Book("a", "The Hobbit", 1981, "J.R.R. Tolkien")], "The Hobbit", "Isaac Asimov");

        matches.Should().BeEmpty();
    }

    /// <summary>
    /// An author is required, the same way a year is for a film, a show or a game (owner's rule): a title on
    /// its own identifies nothing, so there is nothing to confirm against.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ConfirmedCreatorMatches_RefusesWithNoCreatorToIdentifyTheWorkBy(string? creator)
    {
        var matches = ReferenceMatchRules.ConfirmedCreatorMatches(
            [Book("a", "The Hobbit", 1981, "J.R.R. Tolkien")], "The Hobbit", creator);

        matches.Should().BeEmpty();
    }

    /// <summary>
    /// Among editions, the year the tenant recorded is what picks theirs - a tie-break, never a filter, which
    /// is the exact inversion of its role in the title+year domains.
    /// </summary>
    [Fact]
    public void ConfirmedCreatorMatches_PrefersTheTenantsOwnEdition_WithoutExcludingTheOthers()
    {
        var candidates = new[]
        {
            Book("a", "The Hobbit", 1981, "J.R.R. Tolkien"),
            Book("b", "The Hobbit", 2012, "J.R.R. Tolkien")
        };

        ReferenceMatchRules.OrderByBestMatch(candidates, "The Hobbit", 2012).First().ExternalId.Should().Be("b");
        ReferenceMatchRules.ConfirmedCreatorMatches(candidates, "The Hobbit", "Tolkien").Should().HaveCount(2);
    }

    /// <summary>
    /// Loose matching drops "the", which is right across catalogues and wrong against tenant-typed text:
    /// measured live, TMDB answers "Alien" (1979) with both <i>Alien</i> and <i>The Alien</i>, two different
    /// films of the same year. The exactly-spelled candidate wins rather than the pair being reported as an
    /// ambiguity the tenant had already resolved by typing one of them.
    /// </summary>
    [Fact]
    public void ConfirmedMatches_PrefersTheExactlySpelledTitle_WhenLooseMatchingWouldConflateTwoFilms()
    {
        var matches = ReferenceMatchRules.ConfirmedMatches(
            [
                new TmdbSearchResult("348", "Alien", 1979, null, null),
                new TmdbSearchResult("1309211", "The Alien", 1979, null, null)
            ],
            "Alien", 1979);

        matches.Should().ContainSingle().Which.TmdbId.Should().Be("348");
    }

    /// <summary>
    /// The loose tier still does its job when nothing matches exactly - TMDB spells the 2024 show "Shōgun"
    /// where a tenant types "Shogun", and that must still link.
    /// </summary>
    [Fact]
    public void ConfirmedMatches_StillMatchesLoosely_WhenNoCandidateIsSpelledExactly()
    {
        var matches = ReferenceMatchRules.ConfirmedMatches(
            [
                new TmdbSearchResult("126308", "Shōgun", 2024, null, null),
                new TmdbSearchResult("13862", "Shōgun", 1980, null, null)
            ],
            "Shogun", 2024);

        matches.Should().ContainSingle().Which.TmdbId.Should().Be("126308");
    }
}
