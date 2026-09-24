using Keeptrack.Common.System;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// A provider's search result reduced to what identity is decided on. Implemented by every domain's own
/// search-result record so one set of matching rules can read all five.
/// </summary>
public interface IReferenceSearchCandidate
{
    string Title { get; }

    int? Year { get; }
}

/// <summary>
/// A candidate in a domain whose identity is the title plus the person or group who made it - books and
/// albums. <see cref="Creator"/> is that domain's own field under one name (an author, an artist), so the
/// shared rules never have to know which.
/// </summary>
public interface ICreatorSearchCandidate : IReferenceSearchCandidate
{
    string? Creator { get; }
}

/// <summary>
/// When a provider's candidate is the same work as the one being looked for. One declaration, read by
/// everything that has to answer that question in every reference-linked domain: the client search policies
/// rank candidates with it, and <c>ReferenceEnrichmentService</c> confirms automatic resolution, the detail
/// page's "check for reference match" and video game provider adoption with it - so what a picker puts first
/// and what links unattended can never drift apart.
/// <para>
/// <b>There are two identity shapes here, and they are a genuine difference between domains rather than an
/// inconsistency to flatten.</b> A film, a show and a game are identified by a title and a <i>year</i>: two
/// different works sharing a title is ordinary (IGDB holds eight games named exactly "Resident Evil 2", TMDB
/// holds a "Road House" from 1989 and another from 2024, and six shows named "The Office"), so the year is the
/// only thing that tells them apart. A book and an album are identified by a title and a <i>creator</i>:
/// measured live, Google Books answers <c>intitle:The Hobbit+inauthor:Tolkien</c> with 300 volumes whose first
/// page alone spans 1981, 1999, 2011 and 2012 - all one book. Requiring a year there would refuse every
/// edition of every work, so for those two domains the year is a tie-break and never a filter.
/// </para>
/// <para>
/// What both shapes share is the rule that matters: a candidate must be <b>named</b> the work before anything
/// else about it is considered. Trusting that a provider returned exactly one row instead reads a property of
/// the <i>search</i> as a property of the <i>answer</i>, and is wrong in both directions - measured live,
/// <c>search/tv?query=Fallout&amp;first_air_date_year=2025</c> returns exactly one result and it is
/// "Thirst Trap: The Fame. The Fantasy. The Fallout.", while an ordinary <c>The Bear</c> (2022) returns eight
/// and links nothing at all.
/// </para>
/// </summary>
public static class ReferenceMatchRules
{
    /// <summary>The candidate is released in the year that was asked for - or none was asked for.</summary>
    public const int YearAgrees = 0;

    /// <summary>The provider reports no year for this candidate. Missing data, not a disagreement.</summary>
    public const int YearUnknown = 1;

    /// <summary>The candidate is released in a different year. A disagreement, and never a confirmation.</summary>
    public const int YearContradicts = 2;

    /// <summary>
    /// How well a candidate's year agrees with the one that was asked for, best first - the three states in
    /// this file's constants.
    /// <para>
    /// The middle rung is why this is not a boolean, and it is a measured distinction in both directions. Fold
    /// <see cref="YearUnknown"/> into <see cref="YearContradicts"/> and a provider that simply has no date for
    /// a work discards the right answer; fold it into <see cref="YearAgrees"/> and it counts as confirmation -
    /// which floated IGDB's undated "Resident Evil" above the 2002 remake for a search that plainly asked for
    /// 2002, and left the undated "Resident Evil 2" blocking automatic resolution of the 2019 one.
    /// </para>
    /// <para>
    /// With no year requested every candidate ranks <see cref="YearAgrees"/>, which is what leaves a caller
    /// that supplies none exactly where it was: relying on the title and the provider's own relevance order.
    /// </para>
    /// </summary>
    public static int YearRank(int? candidateYear, int? requestedYear) =>
        requestedYear is null || candidateYear == requestedYear ? YearAgrees
        : candidateYear is null ? YearUnknown
        : YearContradicts;

    /// <summary>
    /// Candidates ordered by how well they answer "is this <paramref name="title"/> (<paramref name="year"/>)",
    /// best first - a perfect match ahead of everything, then whatever is closest to what was asked for.
    /// <para>
    /// One ordering for every surface that shows a human a list of candidates, in every domain: a provider
    /// search's results, the admin reconciliation row, and the shortlist that unranked substring queries are
    /// cut down to. They were separate opinions about the same question, and a candidate list is exactly where
    /// an inconsistency wastes someone's time.
    /// </para>
    /// <para>
    /// The keys, in order. <b>Naming the work</b> comes first, so a perfect match cannot be displaced by
    /// anything - it is the answer, and every other candidate is at best a guess. <b>The year</b> is next: for
    /// the title+year domains it is what identifies one work among namesakes, and for books and albums it is
    /// exactly here that it earns its keep as a tie-break, preferring the tenant's own edition among many
    /// without ever excluding the others. <b>Then title distance</b>, which orders the candidates that are not
    /// this work at all: an edition, a DLC pack, a bundle or a live broadcast is spelled as the work plus
    /// something, so the shortest is the closest thing to what was asked for - measured, this is what puts
    /// "Marvel's Avengers" ahead of the 40 crossovers containing both its words, and Radiohead's "Kid A" ahead
    /// of "Kid A (The World Premier Broadcast)". The title breaks the last ties so the order is total, and
    /// therefore stable across identical requests.
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
    /// The candidates confirmed to be <paramref name="title"/> (<paramref name="year"/>) in a domain where the
    /// year is the identity - named the same work under <see cref="TitleNormalizer.LooselyEqual"/>, and
    /// agreeing about the year as well as any candidate does.
    /// <para>
    /// Callers act only on a *single* confirmed match and leave anything else for a human, so what this returns
    /// is a shortlist rather than a verdict: several means "don't guess", none means "nothing here is this
    /// work".
    /// </para>
    /// <para>
    /// <b>Only the best year tier that any candidate reaches is returned</b>, which is the whole point of
    /// asking for a year. A search for "Resident Evil 2" (2019) finds the 2019 game *and* an undated entry of
    /// the same name; keeping both would report an ambiguity the requested year has already resolved, and
    /// nothing further could ever resolve it - the undated entry has no year to be told apart by. A candidate
    /// whose year contradicts the request is never confirmed at all, however alone it is: that is the case
    /// where a title match is most likely to be a different work entirely (a remake, a same-named sequel), and
    /// linking it is the silent data loss this whole rule exists to avoid.
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
    /// The candidates that name <paramref name="title"/>: the ones spelled exactly that way if there are any,
    /// and only otherwise the ones that match loosely.
    /// <para>
    /// <b>The two tiers exist because loose matching deliberately discards real words.</b>
    /// <see cref="TitleNormalizer.NormalizeLoose"/> drops "the" and every parenthesised group, which is right
    /// when comparing one provider's canonical title against another's - it is what lets
    /// <c>Mass Effect: Legendary Edition</c> meet <c>Mass Effect Legendary Edition</c> - but it also makes
    /// genuinely different works collide. Measured live: TMDB answers <c>Alien</c> (1979) with both <i>Alien</i>
    /// and <i>The Alien</i>, two different films from the same year that loose matching cannot tell apart, so
    /// the search reported an ambiguity where the tenant had in fact typed one of the two titles exactly.
    /// </para>
    /// <para>
    /// Preferring the exact spelling resolves that without loosening anything: an exact match is strictly
    /// better evidence than a loose one, so a loose-only candidate can never displace it, and when nothing
    /// matches exactly the loose tier behaves exactly as it did before - which is what still links
    /// <c>Shogun</c> (2024) to TMDB's <i>Shōgun</i>.
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
    /// The candidates confirmed to be <paramref name="title"/> by <paramref name="creator"/> in a domain where
    /// the creator is the identity - books and albums - best first, so a caller links
    /// <c>[0]</c> and refuses an empty list.
    /// <para>
    /// <b>Several results here are editions, not an ambiguity</b>, and that is the one place this differs from
    /// <see cref="ConfirmedMatches"/>. Measured live, Google Books returns 300 volumes for "The Hobbit" by
    /// Tolkien and Discogs returns two masters for "Thriller" by Michael Jackson; every one of them is the same
    /// work, so refusing to choose would mean no book and few albums could ever link. The reference document
    /// describes the work rather than a pressing or a printing, so any confirmed candidate is a right answer
    /// and <see cref="OrderByBestMatch"/> only decides which is the *closest* one - preferring the tenant's own
    /// year when they recorded one, and the plain title over a longer variant.
    /// </para>
    /// <para>
    /// The candidates are deliberately <b>not</b> required to agree with each other about the creator, only
    /// with the one that was asked for. Google Books credits the same book to "J.R.R. Tolkien",
    /// "J. R. R. Tolkien" and "John Ronald Reuel Tolkien", so demanding they agree would read one author as
    /// three and refuse the very case this exists for. Every candidate has already matched what the tenant
    /// supplied, which is what the question was.
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
    /// Whether a candidate's creator is the one that was asked for, allowing either to be the fuller form of
    /// the other: a tenant records "Tolkien" where Google Books credits "J.R.R. Tolkien", and BnF's parsed
    /// "LastName, FirstName" shape contributes only the first credited name of a multi-author record.
    /// <para>
    /// Whole-word containment under <see cref="TitleNormalizer.NormalizeLoose"/> in both directions, so
    /// punctuation and accents can't separate two spellings of one name while a genuinely different person is
    /// still rejected - the same client-side re-check <c>BnfClient.AuthorMatches</c> applies to a provider
    /// clause that is not a strict filter either.
    /// </para>
    /// </summary>
    public static bool CreatorMatches(string? candidateCreator, string requestedCreator) =>
        !string.IsNullOrWhiteSpace(candidateCreator)
        && (TitleNormalizer.LooselyContains(candidateCreator, requestedCreator)
            || TitleNormalizer.LooselyContains(requestedCreator, candidateCreator));
}
