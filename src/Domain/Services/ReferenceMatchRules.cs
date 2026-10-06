using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Services;

/// <summary>
/// A provider's search result reduced to what identity is decided on.
/// Every domain's search-result record implements it, so one set of matching rules reads all five.
/// </summary>
public interface IReferenceSearchCandidate
{
    string Title { get; }

    int? Year { get; }
}

/// <summary>
/// A candidate in a domain identified by the title plus the person or group who made it: books and albums.
/// <see cref="Creator"/> names that field once (an author, an artist), so the shared rules never need to know which.
/// </summary>
public interface ICreatorSearchCandidate : IReferenceSearchCandidate
{
    string? Creator { get; }
}

/// <summary>
/// When a provider's candidate is the work being looked for.
/// Declared once and read in every reference-linked domain: search policies rank candidates with it, and <c>ReferenceEnrichmentService</c> confirms automatic resolution, the detail page's check and video game adoption with it.
/// What a picker puts first and what links unattended therefore never drift apart.
/// <para>
/// <b>There are two identity shapes, a real difference between domains rather than an inconsistency.</b>
/// A film, a show and a game are a title and a <i>year</i>, since namesakes are ordinary: IGDB holds eight games named "Resident Evil 2", TMDB a "Road House" from 1989 and one from 2024, and six shows named "The Office".
/// A book and an album are a title and a <i>creator</i>: Google Books answers <c>intitle:The Hobbit+inauthor:Tolkien</c> with 300 volumes spanning decades, all one book.
/// Requiring a year there would refuse every edition, so for those domains the year breaks ties and never filters.
/// </para>
/// <para>
/// Both shapes share the rule that matters: a candidate must be <b>named</b> the work before anything else counts.
/// Trusting that a provider returned exactly one row reads a property of the search as one of the answer, and fails both ways.
/// <c>search/tv?query=Fallout&amp;first_air_date_year=2025</c> returns one result, "Thirst Trap: The Fame. The Fantasy. The Fallout.", while an ordinary <c>The Bear</c> (2022) returns eight and would link nothing.
/// </para>
/// </summary>
public static class ReferenceMatchRules
{
    /// <summary>The candidate is released in the requested year, or no year was requested.</summary>
    public const int YearAgrees = 0;

    /// <summary>The provider reports no year for this candidate: missing data, not a disagreement.</summary>
    public const int YearUnknown = 1;

    /// <summary>The candidate is released in a different year: a disagreement, never a confirmation.</summary>
    public const int YearContradicts = 2;

    /// <summary>
    /// How well a candidate's year agrees with the requested one, best first, as the three constants above.
    /// <para>
    /// The middle rung is why this is not a boolean.
    /// Counting <see cref="YearUnknown"/> as a contradiction discards a right answer the provider has no date for.
    /// Counting it as agreement floats an undated namesake above the real match: IGDB's undated "Resident Evil" above the 2002 remake asked for, and the undated "Resident Evil 2" blocking the 2019 one.
    /// </para>
    /// <para>
    /// With no year requested every candidate ranks <see cref="YearAgrees"/>, so a caller without a year relies on the title and the provider's order.
    /// </para>
    /// </summary>
    public static int YearRank(int? candidateYear, int? requestedYear) =>
        requestedYear is null || candidateYear == requestedYear ? YearAgrees
        : candidateYear is null ? YearUnknown
        : YearContradicts;

    /// <summary>
    /// Candidates ordered by how well they are <paramref name="title"/> (<paramref name="year"/>), best first: a perfect match ahead of everything, then the closest.
    /// <para>
    /// One ordering for every list of candidates shown to a human, in every domain: provider search results, the admin reconciliation row, and the shortlist substring queries are cut down to.
    /// </para>
    /// <para>
    /// The keys, in order:
    /// <b>naming the work</b>, so nothing displaces a perfect match;
    /// <b>the year</b>, which tells namesakes apart, and for books and albums prefers the tenant's edition without excluding the others;
    /// <b>title distance</b>, which orders what is not this work, since an edition, a DLC, a bundle or a live broadcast is the work plus something.
    /// That puts "Marvel's Avengers" ahead of 40 crossovers containing both words, and "Kid A" ahead of "Kid A (The World Premier Broadcast)".
    /// The title breaks the last ties, so the order is total and stable across identical requests.
    /// </para>
    /// </summary>
    public static IEnumerable<T> OrderByBestMatch<T>(IEnumerable<T> candidates, string title, int? year)
        where T : IReferenceSearchCandidate
    {
        var target = TitleNormalizer.NormalizeLoose(title).Length;
        return candidates
            .OrderBy(candidate => TitleNormalizer.LooselyEqual(candidate.Title, title) ? 0 : 1)
            .ThenBy(candidate => YearRank(candidate.Year, year))
            .ThenBy(candidate => Math.Abs(TitleNormalizer.NormalizeLoose(candidate.Title).Length - target))
            .ThenBy(candidate => candidate.Title, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The candidates confirmed to be <paramref name="title"/> (<paramref name="year"/>) where the year is the identity: named the work under <see cref="TitleNormalizer.LooselyEqual"/>, and agreeing about the year as well as any candidate does.
    /// <para>
    /// Callers act only on a single confirmed match, so this is a shortlist rather than a verdict: several means "do not guess", none means "nothing here is this work".
    /// </para>
    /// <para>
    /// <b>Only the best year tier any candidate reaches is returned</b>, which is the point of asking for a year.
    /// "Resident Evil 2" (2019) finds the 2019 game and an undated namesake, and keeping both would report an ambiguity the year already resolved, one nothing else could resolve.
    /// A candidate whose year contradicts the request is never confirmed, however alone it is.
    /// That is where a title match is most likely another work (a remake, a namesake sequel), and linking it is the silent data loss this rule prevents.
    /// </para>
    /// </summary>
    public static IReadOnlyList<T> ConfirmedMatches<T>(IEnumerable<T> candidates, string title, int? year)
        where T : IReferenceSearchCandidate
    {
        var named = NamedTheSameWork(candidates, title);
        if (named.Count == 0) return named;

        var best = named.Min(candidate => YearRank(candidate.Year, year));
        return best == YearContradicts ? [] : named.Where(candidate => YearRank(candidate.Year, year) == best).ToList();
    }

    /// <summary>
    /// The candidates naming <paramref name="title"/>: those spelled exactly so if there are any, and otherwise those matching loosely.
    /// <para>
    /// <b>Two tiers, because loose matching discards real words.</b>
    /// <see cref="TitleNormalizer.NormalizeLoose"/> drops "the" and parenthesised groups, which lets <c>Mass Effect: Legendary Edition</c> meet <c>Mass Effect Legendary Edition</c>, but also makes different works collide.
    /// TMDB answers <c>Alien</c> (1979) with <i>Alien</i> and <i>The Alien</i>, two films of that year that loose matching cannot tell apart, although the tenant typed one of them exactly.
    /// </para>
    /// <para>
    /// An exact match is better evidence than a loose one, so a loose-only candidate never displaces it.
    /// When nothing matches exactly, the loose tier applies, which still links <c>Shogun</c> (2024) to TMDB's <i>Shōgun</i>.
    /// </para>
    /// </summary>
    private static List<T> NamedTheSameWork<T>(IEnumerable<T> candidates, string title)
        where T : IReferenceSearchCandidate
    {
        var loose = candidates.Where(candidate => TitleNormalizer.LooselyEqual(candidate.Title, title)).ToList();
        var normalizedTitle = TitleNormalizer.Normalize(title);
        var exact = loose.Where(candidate => TitleNormalizer.Normalize(candidate.Title) == normalizedTitle).ToList();
        return exact.Count > 0 ? exact : loose;
    }

    /// <summary>
    /// The candidates confirmed to be <paramref name="title"/> by <paramref name="creator"/> where the creator is the identity (books, albums), best first, so a caller links <c>[0]</c> and refuses an empty list.
    /// <para>
    /// <b>Several results here are editions, not an ambiguity</b>, the one difference from <see cref="ConfirmedMatches"/>.
    /// Google Books returns 300 volumes for "The Hobbit" by Tolkien, and Discogs two masters for "Thriller" by Michael Jackson, each the same work, so refusing to choose would link no book and few albums.
    /// The reference describes the work rather than a printing, so any confirmed candidate is right, and <see cref="OrderByBestMatch"/> only picks the closest: the tenant's year when recorded, and the plain title over a longer variant.
    /// </para>
    /// <para>
    /// The candidates must agree with the requested creator, <b>not</b> with each other.
    /// Google Books credits one book to "J.R.R. Tolkien", "J. R. R. Tolkien" and "John Ronald Reuel Tolkien", so demanding agreement would read one author as three.
    /// </para>
    /// </summary>
    public static IReadOnlyList<T> ConfirmedCreatorMatches<T>(IEnumerable<T> candidates, string title, string? creator)
        where T : ICreatorSearchCandidate
    {
        if (string.IsNullOrWhiteSpace(creator)) return [];

        var named = NamedTheSameWork(candidates, title).Where(candidate => CreatorMatches(candidate.Creator, creator));
        return OrderByBestMatch(named, title, null).ToList();
    }

    /// <summary>
    /// Whether a candidate's creator is the requested one, either being possibly the fuller form of the other.
    /// A tenant records "Tolkien" where Google Books credits "J.R.R. Tolkien", and BnF's parsed "LastName, FirstName" gives only the first name of a multi-author record.
    /// <para>
    /// Whole-word containment under <see cref="TitleNormalizer.NormalizeLoose"/> both ways, so punctuation and accents do not separate two spellings of one name, while a different person is still rejected.
    /// </para>
    /// </summary>
    public static bool CreatorMatches(string? candidateCreator, string requestedCreator) =>
        !string.IsNullOrWhiteSpace(candidateCreator)
        && (TitleNormalizer.LooselyContains(candidateCreator, requestedCreator)
            || TitleNormalizer.LooselyContains(requestedCreator, candidateCreator));
}
