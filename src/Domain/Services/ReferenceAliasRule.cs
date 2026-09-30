using System.Collections.Generic;
using System.Linq;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// What a <see cref="ReferenceMatchModel"/> must carry to be worth storing at all, declared once per domain and read by everything that writes one - the enrichment service's merge, and each reference repository's canonical-alias safety net.
/// <para>
/// An alias is <b>the local match key</b>: the whole point of <c>matched_aliases</c> is that a title someone already resolved never has to be resolved again, so a lookup finds the reference without a provider call.
/// That only works while every stored entry names exactly one work.
/// An entry missing the field that identifies the work is not a weaker key, it is a key that answers questions it was never confirmed for - a title-only alias for "Resident Evil 2" claims all eight games IGDB holds under that name, and a creator-less one for "Echoes" claims every novel ever titled that.
/// Both were being written, on every resolve where the tenant had left the year (or the provider the author) blank.
/// </para>
/// <para>
/// So an incomplete alias is <b>refused</b> rather than stored and worked around later: the cost of refusing is one provider call the next time that item is checked, and the cost of storing is a wrong link nothing downstream ever reports.
/// </para>
/// </summary>
public sealed class ReferenceAliasRule
{
    /// <summary>
    /// Films, shows and games: a title <b>plus a year</b>.
    /// Same-titled works are ordinary in all three catalogues, so the year is the only thing that separates them - which is exactly why automatic resolution refuses to act without one (see <c>ReferenceMatchRules</c>), and why an alias without one is not a match key.
    /// </summary>
    public static readonly ReferenceAliasRule TitleAndYear = new(carriesYear: true, requiresYear: true, requiresCreator: false, carriesIsbn: false);

    /// <summary>
    /// Albums: a title <b>plus an artist</b>, and deliberately no year.
    /// One release exists as many pressings under as many years, so the year narrows nothing an artist has not already settled - while carrying it would mint one alias per year any tenant ever typed for the same record.
    /// </summary>
    public static readonly ReferenceAliasRule TitleAndCreator = new(carriesYear: false, requiresYear: false, requiresCreator: true, carriesIsbn: false);

    /// <summary>
    /// Books: a title <b>plus an author</b>, the same identity as an album - and unlike an album, the year travels with it whenever one is known, since a book genuinely is republished as revisions the year tells apart, so an alias records the printing it was confirmed under.
    /// An ISBN, which names one printing outright, is enough on its own.
    /// <para>
    /// The year is <b>recorded, not required</b>, and that distinction is load-bearing.
    /// Requiring it would mean a book whose provider reports no year stores no alias at all - and an item with no alias is not merely unmatched, it is <i>actively unlinked</i> the next time anyone presses "check for reference match", since finding nothing is what clears a link.
    /// It would also buy no disambiguation: two different works sharing both a title and an author's name are the one case the year-agnostic lookup already refuses to choose in, and every other case is one work under several years.
    /// </para>
    /// </summary>
    public static readonly ReferenceAliasRule TitleAndCreatorWithYear = new(carriesYear: true, requiresYear: false, requiresCreator: true, carriesIsbn: true);

    private readonly bool _carriesYear;

    private readonly bool _requiresYear;

    private readonly bool _requiresCreator;

    private readonly bool _carriesIsbn;

    /// <summary>
    /// "Carries" and "requires" are separate on purpose: a field can be worth recording without being what identifies the work (a book's edition year), and one that identifies nothing is dropped rather than stored (an album's pressing year).
    /// A creator is only ever recorded where it is required.
    /// </summary>
    private ReferenceAliasRule(bool carriesYear, bool requiresYear, bool requiresCreator, bool carriesIsbn)
    {
        _carriesYear = carriesYear;
        _requiresYear = requiresYear;
        _requiresCreator = requiresCreator;
        _carriesIsbn = carriesIsbn;
    }

    /// <summary>
    /// The alias for one confirmed combination, or <b>null when the combination does not identify a work</b> under this rule.
    /// Title and creator come back normalized (<see cref="TitleNormalizer.Normalize"/>, the same form every lookup filters with), and any field this domain's key has no dimension for is dropped rather than stored - a stray value there would only ever produce a second alias meaning exactly what an existing one already means.
    /// </summary>
    public ReferenceMatchModel? Build(string? title, int? year, string? creator, string? isbn)
    {
        if (string.IsNullOrWhiteSpace(title)) return null;

        var normalizedTitle = TitleNormalizer.Normalize(title);
        var normalizedCreator = _requiresCreator && !string.IsNullOrWhiteSpace(creator) ? TitleNormalizer.Normalize(creator) : null;
        var storedYear = _carriesYear ? year : null;
        var storedIsbn = _carriesIsbn && !string.IsNullOrWhiteSpace(isbn) ? isbn.Trim() : null;

        var identified = (!_requiresYear || storedYear is not null) && (!_requiresCreator || normalizedCreator is not null);
        if (!identified && storedIsbn is null) return null;

        return new ReferenceMatchModel { Title = normalizedTitle, Year = storedYear, Creator = normalizedCreator, Isbn = storedIsbn };
    }

    /// <summary>
    /// Whatever a reference document already remembered, plus every one of <paramref name="candidates"/> this rule accepts and does not already hold.
    /// Never removes: an alias is a fact someone confirmed, and the combinations a work has been recorded under only accumulate.
    /// </summary>
    public List<ReferenceMatchModel> Merge(List<ReferenceMatchModel>? existing, params (string? Title, int? Year, string? Creator, string? Isbn)[] candidates)
    {
        var result = new List<ReferenceMatchModel>(existing ?? []);

        foreach (var (title, year, creator, isbn) in candidates)
        {
            var alias = Build(title, year, creator, isbn);
            if (alias is null) continue;
            if (result.Any(recorded => recorded.Matches(alias.Title, alias.Year, alias.Creator, alias.Isbn))) continue;

            result.Add(alias);
        }

        return result;
    }

    /// <summary>
    /// Adds a document's own canonical title/year to <paramref name="aliases"/> when that pair is a complete key under this rule - the repositories' safety net for a caller that upserted without going through the enrichment service's merge.
    /// <para>
    /// It adds nothing at all for a domain whose key needs a creator, and that is not a gap: a book/album reference document carries only its author/artist <i>reference id</i>, never the name, so there is nothing here to build a complete alias from.
    /// Writing the creator-less one anyway is precisely the half-key this class exists to refuse - and it was being written on every single upsert.
    /// </para>
    /// </summary>
    public void EnsureCanonical(List<ReferenceMatchModel> aliases, string title, int? year)
    {
        var alias = Build(title, year, null, null);
        if (alias is null) return;
        if (aliases.Any(recorded => recorded.Matches(alias.Title, alias.Year, alias.Creator, alias.Isbn))) return;

        aliases.Add(alias);
    }
}
