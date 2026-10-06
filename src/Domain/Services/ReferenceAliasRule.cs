using System.Collections.Generic;
using System.Linq;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// What a <see cref="ReferenceMatchModel"/> must carry to be stored, declared once per domain and read by everything writing one: the enrichment merge and each reference repository's canonical-alias safety net.
/// <para>
/// An alias is <b>the local match key</b>: a title someone already resolved is found again without a provider call.
/// That only works while every stored entry names exactly one work.
/// An entry missing the field that identifies the work is not a weaker key but one answering questions nobody confirmed.
/// A title-only "Resident Evil 2" claims all eight games IGDB holds under that name, and a creator-less "Echoes" claims every novel with that title.
/// </para>
/// <para>
/// An incomplete alias is therefore <b>refused</b> rather than stored.
/// Refusing costs one provider call the next time the item is checked, and storing costs a wrong link that nothing reports.
/// </para>
/// </summary>
public sealed class ReferenceAliasRule
{
    /// <summary>
    /// Films, shows and games: a title <b>plus a year</b>.
    /// Same-titled works are ordinary in all three catalogues, and the year is what separates them.
    /// That is why automatic resolution refuses to act without one (see <c>ReferenceMatchRules</c>), and why an alias without one is no match key.
    /// </summary>
    public static readonly ReferenceAliasRule TitleAndYear = new(carriesYear: true, requiresYear: true, requiresCreator: false, carriesIsbn: false);

    /// <summary>
    /// Albums: a title <b>plus an artist</b>, and no year.
    /// One release exists as many pressings under many years, so the year narrows nothing the artist has not settled, and carrying it would mint one alias per year typed for the same record.
    /// </summary>
    public static readonly ReferenceAliasRule TitleAndCreator = new(carriesYear: false, requiresYear: false, requiresCreator: true, carriesIsbn: false);

    /// <summary>
    /// Books: a title <b>plus an author</b>, like an album.
    /// Unlike an album, the year travels with it when known, since a book is republished as revisions the year tells apart, so an alias records the printing it was confirmed under.
    /// An ISBN, which names one printing outright, is enough on its own.
    /// <para>
    /// The year is <b>recorded, not required</b>, and that distinction matters.
    /// Requiring it, a book whose provider reports no year would store no alias, and the next "check for reference match" would then unlink it, since finding nothing clears a link.
    /// Nor would it disambiguate anything: two works sharing a title and an author's name are the case the lookup ignoring the year already refuses, and every other case is one work under several years.
    /// </para>
    /// </summary>
    public static readonly ReferenceAliasRule TitleAndCreatorWithYear = new(carriesYear: true, requiresYear: false, requiresCreator: true, carriesIsbn: true);

    private readonly bool _carriesYear;

    private readonly bool _requiresYear;

    private readonly bool _requiresCreator;

    private readonly bool _carriesIsbn;

    /// <summary>
    /// "Carries" and "requires" differ: a field can be worth recording without identifying the work (a book's edition year), and one identifying nothing is dropped (an album's pressing year).
    /// A creator is only recorded where it is required.
    /// </summary>
    private ReferenceAliasRule(bool carriesYear, bool requiresYear, bool requiresCreator, bool carriesIsbn)
    {
        _carriesYear = carriesYear;
        _requiresYear = requiresYear;
        _requiresCreator = requiresCreator;
        _carriesIsbn = carriesIsbn;
    }

    /// <summary>
    /// The alias for one confirmed combination, or <b>null when it does not identify a work</b> under this rule.
    /// Title and creator come back normalized (<see cref="TitleNormalizer.Normalize"/>), the form every lookup filters with.
    /// A field outside this domain's key is dropped, since it would only produce a second alias meaning the same as an existing one.
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
    /// The aliases a reference already holds, plus every one of <paramref name="candidates"/> this rule accepts and it does not hold yet.
    /// Never removes any, since an alias is a fact someone confirmed.
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
    /// Adds a document's canonical title and year to <paramref name="aliases"/> when that pair is a complete key under this rule.
    /// It is the repositories' safety net for a caller upserting without the enrichment merge.
    /// <para>
    /// It adds nothing for a domain whose key needs a creator.
    /// A book or album reference carries only its author's or artist's reference id, never the name, so a complete alias cannot be built here, and a creator-less one is the half key this class refuses.
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
