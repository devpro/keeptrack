using AwesomeAssertions;
using Keeptrack.Common.System;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

/// <summary>
/// The loose matcher exists to pair one provider's canonical title with another's, so every case here is a
/// real divergence taken from live RAWG and IGDB records - the ones that left a third of a real catalogue
/// unable to adopt the current default provider's id, and kept those same games in the owner's Explore feed.
/// </summary>
[Trait("Category", "UnitTests")]
public class TitleNormalizerTest
{
    [Theory]
    // punctuation only: IGDB drops the colon RAWG keeps
    [InlineData("Mass Effect: Legendary Edition", "Mass Effect Legendary Edition")]
    // the article: IGDB's record is "The Final Cut", RAWG's is "Final Cut"
    [InlineData("Disco Elysium: Final Cut", "Disco Elysium: The Final Cut")]
    // RAWG disambiguates a remake by appending the original's year to the title itself
    [InlineData("GoldenEye 007 (1997)", "GoldenEye 007")]
    [InlineData("Resident Evil 2 (1998)", "Resident Evil 2")]
    [InlineData("DOOM (2016)", "Doom")]
    // accents, spacing and case
    [InlineData("Pokémon Scarlet", "Pokemon Scarlet")]
    [InlineData("NieR:Automata", "NieR: Automata")]
    [InlineData("Ratchet & Clank", "Ratchet and Clank")]
    // an apostrophe one catalogue writes and the other doesn't - dropped rather than spaced, or these
    // normalize to "assassin s creed" and match neither spelling
    [InlineData("Assassin's Creed", "Assassins Creed")]
    [InlineData("Marvel’s Spider-Man", "Marvels Spider Man")]
    public void NormalizeLoose_TreatsProviderSpellingsOfOneWorkAsEqual(string left, string right) =>
        TitleNormalizer.LooselyEqual(left, right).Should().BeTrue();

    [Theory]
    // an edition is its own product and must stay distinct - adopting one for the other is a wrong link,
    // which is worse than an entry in the admin reconciliation queue
    [InlineData("NieR:Automata Game of the YoRHa Edition", "NieR: Automata")]
    [InlineData("Red Dead Redemption 2", "Red Dead Redemption")]
    // sequels, and the deliberate decision not to equate roman numerals with digits
    [InlineData("Final Fantasy IV", "Final Fantasy 4")]
    [InlineData("Portal 2", "Portal")]
    public void NormalizeLoose_KeepsGenuinelyDifferentWorksApart(string left, string right) =>
        TitleNormalizer.LooselyEqual(left, right).Should().BeFalse();

    [Theory]
    // confirmed against the live IGDB API: querying with the suffix returns nothing at all - not a bad
    // candidate list, an empty one - from both its exact-name lookup and its relevance search
    [InlineData("GoldenEye 007 (1997)", "GoldenEye 007")]
    [InlineData("God of War (2018)", "God of War")]
    [InlineData("Demon's Souls (2020)", "Demon's Souls")]
    // everything else survives untouched, so the result is still a title a provider could hold verbatim
    [InlineData("Marvel's Spider-Man", "Marvel's Spider-Man")]
    [InlineData("Pokémon Scarlet", "Pokémon Scarlet")]
    public void StripDisambiguator_RemovesOnlyTheParenthesisedGroup(string title, string expected) =>
        TitleNormalizer.StripDisambiguator(title).Should().Be(expected);

    [Theory]
    // the rows a provider's search could not parse, all confirmed against the live IGDB API: it answers the
    // left-hand string with nothing (or with unrelated games) and the right-hand one with the game itself
    [InlineData("NieR:Automata", "NieR Automata")]
    [InlineData("Pokémon: Let's Go, Pikachu! and Eevee!", "Pokemon Lets Go Pikachu and Eevee")]
    [InlineData("NieR Replicant v1.22474487139", "NieR Replicant v1 22474487139")]
    [InlineData("Marvel's Avengers", "Marvels Avengers")]
    // unlike NormalizeLoose this is a query, not a key: every word survives (including "the") and so does the
    // casing, because the result still has to read as a title the provider could hold
    [InlineData("Disco Elysium: The Final Cut", "Disco Elysium The Final Cut")]
    [InlineData("GoldenEye 007 (1997)", "GoldenEye 007 1997")]
    public void ToProviderQuery_ReducesATitleToWordsAProviderSearchCanParse(string title, string expected) =>
        TitleNormalizer.ToProviderQuery(title).Should().Be(expected);

    [Theory]
    // the album itself, and the editions/compilations that legitimately carry its name
    [InlineData("Discovery", "Discovery")]
    [InlineData("Homework / Discovery", "Discovery")]
    [InlineData("Nevermind (Demo & Outtakes)", "Nevermind")]
    [InlineData("Nevermind, It's An Interview", "Nevermind")]
    [InlineData("Sabbath Bloody Sabbath", "Sabbath")]
    // the same spelling divergences NormalizeLoose already absorbs, mid-title
    [InlineData("Blue / Ladies Of The Canyon", "Blue")]
    [InlineData("Ratchet and Clank Collection", "Ratchet & Clank")]
    public void LooselyContains_KeepsAResultWhoseTitleActuallyCarriesTheSearchedOne(string candidate, string searched) =>
        TitleNormalizer.LooselyContains(candidate, searched).Should().BeTrue();

    [Theory]
    // real Discogs hits for q=Discovery&artist=Daft Punk - free text matched something other than the title
    [InlineData("Live @ Rex Club, Paris", "Discovery")]
    [InlineData("MP3 Collection", "Discovery")]
    // q=Sabbath: the word only ever occurs in the artist name, "Black Sabbath"
    [InlineData("Paranoid", "Sabbath")]
    // whole words, so a search doesn't keep every title that merely starts with the same letters
    [InlineData("Blueprint", "Blue")]
    [InlineData("Ghostbusters", "Ghost Town")]
    public void LooselyContains_DiscardsAResultThatMatchedOnSomethingOtherThanItsTitle(string candidate, string searched) =>
        TitleNormalizer.LooselyContains(candidate, searched).Should().BeFalse();

    /// <summary>A title with nothing left to compare must not filter a caller's results down to none.</summary>
    [Fact]
    public void LooselyContains_MatchesAnything_WhenTheSearchedTitleNormalizesToNothing() =>
        TitleNormalizer.LooselyContains("Paranoid", "(2)").Should().BeTrue();

    [Fact]
    public void Normalize_StaysStrict_SoTenantTypedTextIsNotConflated()
    {
        // the stored alias/TitleNormalized key is matched against what a tenant typed, where losing this much
        // information would start merging different items - only provider-to-provider matching goes loose
        TitleNormalizer.Normalize("Mass Effect: Legendary Edition").Should().Be("mass effect: legendary edition");
        TitleNormalizer.Normalize("  Portal 2 ").Should().Be("portal 2");
    }
}
