using AwesomeAssertions;
using Keeptrack.WebApi.ReferenceData;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// Reading an identifier back out of a provider page address is the admin reconciliation screen's escape
/// hatch for a game no search query reaches, so what it accepts matters in both directions: a URL it fails to
/// read leaves that row stuck, and ordinary search text it mistakes for an address turns "look this up" into
/// "look nothing up".
/// </summary>
[Trait("Category", "UnitTests")]
public class ProviderWebLinksTest
{
    [Theory]
    // the addresses a human copies out of the browser, from both video game providers
    [InlineData("https://www.igdb.com/games/marvels-avengers", "marvels-avengers")]
    [InlineData("https://www.igdb.com/games/marvels-avengers/", "marvels-avengers")]
    [InlineData("https://rawg.io/games/nier-automata", "nier-automata")]
    // pasted with the tracking query string the site adds, and with stray whitespace
    [InlineData("https://www.igdb.com/games/nier-automata?utm_source=x", "nier-automata")]
    [InlineData("  https://www.igdb.com/games/nier-automata  ", "nier-automata")]
    // and the provider's own numeric id, which is just as unambiguous
    [InlineData("26950", "26950")]
    public void TryReadIdentifier_ReadsTheIdentifierAProviderKeysItsPageOn(string text, string expected)
    {
        ProviderWebLinks.TryReadIdentifier(text, out var identifier).Should().BeTrue();
        identifier.Should().Be(expected);
    }

    [Theory]
    // every one of these is a perfectly ordinary thing to search a provider for, and a hyphenated word looks
    // exactly like a page slug - so nothing short of an address or a number is treated as one
    [InlineData("Half-Life")]
    [InlineData("Marvel's Avengers")]
    [InlineData("nier-automata")]
    [InlineData("Version 1.22474487139")]
    [InlineData("")]
    [InlineData("   ")]
    public void TryReadIdentifier_LeavesOrdinarySearchTextAlone(string text) =>
        ProviderWebLinks.TryReadIdentifier(text, out _).Should().BeFalse();
}
