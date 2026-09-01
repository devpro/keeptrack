using AwesomeAssertions;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class SharedItemMatcherTest
{
    [Fact]
    public void SameNonEmptyReferenceId_Matches_RegardlessOfTitle()
    {
        var a = new ItemMatchKey("ref-1", "The Terminator", 1984, null);
        var b = new ItemMatchKey("ref-1", "Terminator (1984 cut)", 1984, null);

        SharedItemMatcher.Matches(a, b).Should().BeTrue();
    }

    [Fact]
    public void DifferentNonEmptyReferenceIds_DoNotMatch_EvenWithIdenticalTitle()
    {
        var a = new ItemMatchKey("ref-1", "Dune", 2021, null);
        var b = new ItemMatchKey("ref-2", "Dune", 2021, null);

        SharedItemMatcher.Matches(a, b).Should().BeFalse();
    }

    [Fact]
    public void NoReferenceIds_MatchByNormalizedTitleAndYear()
    {
        var a = new ItemMatchKey(null, "  Breaking Bad ", 2008, null);
        var b = new ItemMatchKey("", "breaking bad", 2008, null);

        SharedItemMatcher.Matches(a, b).Should().BeTrue();
    }

    [Fact]
    public void SameTitle_DifferentYear_DoesNotMatch()
    {
        var a = new ItemMatchKey(null, "It", 1990, null);
        var b = new ItemMatchKey(null, "It", 2017, null);

        SharedItemMatcher.Matches(a, b).Should().BeFalse();
    }

    [Fact]
    public void MissingYearOnEitherSide_IsAWildcard()
    {
        var a = new ItemMatchKey(null, "Akira", null, null);
        var b = new ItemMatchKey(null, "Akira", 1988, null);

        SharedItemMatcher.Matches(a, b).Should().BeTrue();
    }

    [Fact]
    public void Books_WithDifferentAuthors_DoNotMatch_EvenWithSameTitleAndYear()
    {
        var a = new ItemMatchKey(null, "Killing Floor", 1997, "Lee Child");
        var b = new ItemMatchKey(null, "Killing Floor", 1997, "Someone Else");

        SharedItemMatcher.Matches(a, b).Should().BeFalse();
    }

    [Fact]
    public void Books_WithSameAuthor_Match()
    {
        var a = new ItemMatchKey(null, "Killing Floor", 1997, "Lee Child");
        var b = new ItemMatchKey(null, "killing floor", 1997, "lee child");

        SharedItemMatcher.Matches(a, b).Should().BeTrue();
    }

    [Fact]
    public void FindMatch_ReturnsTheMatchingItem_OrNull()
    {
        var candidate = new ItemMatchKey(null, "The Wire", 2002, null);
        var existing = new[]
        {
            new Owned("x", new ItemMatchKey(null, "Fringe", 2008, null)),
            new Owned("y", new ItemMatchKey("ref-9", "The Wire", 2002, null))
        };

        SharedItemMatcher.FindMatch(candidate, existing, o => o.Key)!.Id.Should().Be("y");
        SharedItemMatcher.FindMatch(new ItemMatchKey(null, "Lost", 2004, null), existing, o => o.Key).Should().BeNull();
    }

    private sealed record Owned(string Id, ItemMatchKey Key);
}
