using System.Collections.Generic;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

/// <summary>
/// The single declaration of what a matched alias must carry to be stored, per domain (see <see cref="ReferenceAliasRule"/>).
/// An alias is the local match key, and one missing the field identifying the work is not weaker but matches what it was never confirmed for, so building one is refused.
/// </summary>
[Trait("Category", "UnitTests")]
public class ReferenceAliasRuleTest
{
    [Fact]
    public void TitleAndYear_RecordsTheAlias_WhenBothAreKnown()
    {
        var alias = ReferenceAliasRule.TitleAndYear.Build("  The Wire ", 2002, null, null);

        alias.Should().NotBeNull();
        alias!.Title.Should().Be("the wire");
        alias.Year.Should().Be(2002);
        alias.Creator.Should().BeNull();
        alias.Isbn.Should().BeNull();
    }

    /// <summary>
    /// The defect this rule exists for: a title-only alias written for a tenant who recorded no year would match every later lookup for that title, whatever its year.
    /// </summary>
    [Fact]
    public void TitleAndYear_RefusesAnAlias_WithNoYear()
    {
        ReferenceAliasRule.TitleAndYear.Build("The Wire", null, null, null).Should().BeNull();
    }

    [Fact]
    public void TitleAndYear_RefusesAnAlias_WithNoTitle()
    {
        ReferenceAliasRule.TitleAndYear.Build("   ", 2002, null, null).Should().BeNull();
    }

    [Fact]
    public void TitleAndCreator_RecordsTheAlias_WhenBothAreKnown()
    {
        var alias = ReferenceAliasRule.TitleAndCreator.Build("Kid A", 2000, " Radiohead ", null);

        alias.Should().NotBeNull();
        alias!.Title.Should().Be("kid a");
        alias.Creator.Should().Be("radiohead");
    }

    /// <summary>
    /// An album is identified by its title and artist, so the year adds nothing to the key, and carrying it would mint one alias per year any tenant typed for the release.
    /// </summary>
    [Fact]
    public void TitleAndCreator_StoresNoYear_SoOneCombinationIsOneEntry()
    {
        var aliases = ReferenceAliasRule.TitleAndCreator.Merge(null, ("Kid A", 2000, "Radiohead", null), ("Kid A", 2001, "Radiohead", null));

        aliases.Should().ContainSingle();
        aliases[0].Year.Should().BeNull();
    }

    [Fact]
    public void TitleAndCreator_RefusesAnAlias_WithNoCreator()
    {
        ReferenceAliasRule.TitleAndCreator.Build("Kid A", 2000, null, null).Should().BeNull();
    }

    [Fact]
    public void TitleAndCreatorWithYear_RecordsAllThree()
    {
        var alias = ReferenceAliasRule.TitleAndCreatorWithYear.Build("The Hobbit", 2011, "J.R.R. Tolkien", null);

        alias.Should().NotBeNull();
        alias!.Title.Should().Be("the hobbit");
        alias.Year.Should().Be(2011);
        alias.Creator.Should().Be("j.r.r. tolkien");
    }

    /// <summary>
    /// The year is recorded, never required: a book whose provider reports no year still has a complete key in its title and author.
    /// Refusing the alias would leave the reference locally unmatchable, worse than unmatched, since the next "check for reference match" would find nothing and clear the link.
    /// </summary>
    [Fact]
    public void TitleAndCreatorWithYear_RecordsTheAlias_WithNoYearAtAll()
    {
        var alias = ReferenceAliasRule.TitleAndCreatorWithYear.Build("The Hobbit", null, "J.R.R. Tolkien", null);

        alias.Should().NotBeNull();
        alias!.Creator.Should().Be("j.r.r. tolkien");
        alias.Year.Should().BeNull();
    }

    /// <summary>
    /// Where a year is known it is kept, per edition, which makes the exact (title, creator, year) tier precise, and two printings of one work two entries.
    /// </summary>
    [Fact]
    public void TitleAndCreatorWithYear_RecordsOneAliasPerEditionYear()
    {
        var aliases = ReferenceAliasRule.TitleAndCreatorWithYear.Merge(null,
            ("The Hobbit", 1981, "J.R.R. Tolkien", null), ("The Hobbit", 2011, "J.R.R. Tolkien", null));

        aliases.Should().HaveCount(2);
    }

    [Fact]
    public void TitleAndCreatorWithYear_RefusesAnAlias_WithNoCreatorAndNoIsbn()
    {
        ReferenceAliasRule.TitleAndCreatorWithYear.Build("The Hobbit", 2011, null, null).Should().BeNull();
    }

    /// <summary>An ISBN names one printing on its own, so it stands in for the title+creator+year key.</summary>
    [Fact]
    public void TitleAndCreatorWithYear_RecordsAnIsbnAlias_EvenWithNothingElseToIdentifyTheEdition()
    {
        var alias = ReferenceAliasRule.TitleAndCreatorWithYear.Build("The Hobbit", null, null, "9780261102217");

        alias.Should().NotBeNull();
        alias!.Isbn.Should().Be("9780261102217");
    }

    [Fact]
    public void Merge_KeepsWhatIsAlreadyRecorded_AndAddsOnlyWhatIsNew()
    {
        List<ReferenceMatchModel> existing = [new() { Title = "the wire", Year = 2002 }];

        var aliases = ReferenceAliasRule.TitleAndYear.Merge(existing, ("The Wire", 2002, null, null), ("Le Fil", 2002, null, null));

        aliases.Should().HaveCount(2);
        aliases.Should().Contain(a => a.Title == "the wire" && a.Year == 2002);
        aliases.Should().Contain(a => a.Title == "le fil" && a.Year == 2002);
    }

    /// <summary>
    /// Documents written before Mapperly store a null creator as <c>""</c> (see <c>scripts/dedupe-matched-aliases.js</c>),
    /// and reading those as a different creator would append a duplicate on every re-resolve.
    /// </summary>
    [Fact]
    public void Merge_TreatsAnEmptyStoredCreator_AsNoCreator()
    {
        List<ReferenceMatchModel> existing = [new() { Title = "the wire", Year = 2002, Creator = "" }];

        var aliases = ReferenceAliasRule.TitleAndYear.Merge(existing, ("The Wire", 2002, null, null));

        aliases.Should().ContainSingle();
    }

    [Fact]
    public void Merge_DropsACandidateTheDomainCannotIdentify_RatherThanStoringHalfAKey()
    {
        var aliases = ReferenceAliasRule.TitleAndYear.Merge(null, ("The Wire", null, null, null));

        aliases.Should().BeEmpty();
    }

    /// <summary>
    /// The repository safety net: a document's own canonical title/year belongs in its aliases, but only when that pair is a complete key for the domain.
    /// </summary>
    [Fact]
    public void EnsureCanonical_AddsTheDocumentsOwnTitleAndYear_WhenThatPairIsACompleteKey()
    {
        List<ReferenceMatchModel> aliases = [];

        ReferenceAliasRule.TitleAndYear.EnsureCanonical(aliases, "the wire", 2002);

        aliases.Should().ContainSingle(a => a.Title == "the wire" && a.Year == 2002);
    }

    [Fact]
    public void EnsureCanonical_AddsNothing_WhenTheDocumentHasNoYear()
    {
        List<ReferenceMatchModel> aliases = [];

        ReferenceAliasRule.TitleAndYear.EnsureCanonical(aliases, "the wire", null);

        aliases.Should().BeEmpty();
    }

    /// <summary>
    /// A book or album reference document carries only its author or artist <i>reference id</i>, never the name,
    /// so a repository can't build a complete alias, and a creator-less one is the junk key this rule refuses.
    /// </summary>
    [Fact]
    public void EnsureCanonical_AddsNothing_WhenTheDomainNeedsACreatorTheDocumentCannotSupply()
    {
        List<ReferenceMatchModel> aliases = [];

        ReferenceAliasRule.TitleAndCreator.EnsureCanonical(aliases, "kid a", 2000);
        ReferenceAliasRule.TitleAndCreatorWithYear.EnsureCanonical(aliases, "the hobbit", 2011);

        aliases.Should().BeEmpty();
    }
}
