using System;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Keeptrack.Common.System;

/// <summary>
/// Shared title normalization for matching by name across the import pipeline and the reference-data
/// layer - one implementation so both never drift apart on what counts as "the same title".
/// </summary>
public static class TitleNormalizer
{
    public static string Normalize(string title) => title.Trim().ToLowerInvariant();

    /// <summary>
    /// A deliberately looser form of <see cref="Normalize"/>, for matching one <b>provider's</b> canonical
    /// title against another's: diacritics folded, a <c>(1997)</c>-style disambiguation suffix dropped,
    /// punctuation and the article "the" removed, whitespace collapsed.
    /// <para>
    /// It exists because two catalogues name the same work differently in small, systematic ways, confirmed
    /// against real RAWG and IGDB records: <c>Mass Effect: Legendary Edition</c> vs
    /// <c>Mass Effect Legendary Edition</c>, <c>Disco Elysium: Final Cut</c> vs
    /// <c>Disco Elysium: The Final Cut</c>, and RAWG's habit of disambiguating a remake by appending the
    /// original's year (<c>GoldenEye 007 (1997)</c>, <c>Resident Evil 2 (1998)</c>). Exact normalized equality
    /// rejected every one of those, which is what left a third of this database's video game references
    /// unable to adopt the current default provider's id - and, because the Explore exclusion compares titles
    /// the same way, is why those same games kept being suggested to the owner who already had them.
    /// </para>
    /// <para>
    /// It is <b>not</b> a replacement for <see cref="Normalize"/> and never becomes the stored
    /// <c>TitleNormalized</c>/alias key: those are matched against tenant-typed text, where losing this much
    /// information would start conflating genuinely different items. Loose matching is only ever a way to
    /// *shortlist* candidates - every caller still confirms with a compatible year and refuses anything that
    /// isn't a single match, so a false pairing here costs an entry in the admin reconciliation queue rather
    /// than a wrong link.
    /// </para>
    /// <para>
    /// Roman numerals are deliberately left alone (<c>Final Fantasy IV</c> stays distinct from
    /// <c>Final Fantasy 4</c>): the rule would be genuinely ambiguous for one-letter tokens, and an
    /// unmatched pair is a queue entry an admin resolves in one click, while a wrong pair is silent data loss.
    /// </para>
    /// </summary>
    public static string NormalizeLoose(string title)
    {
        var folded = RemoveDiacritics(title).ToLowerInvariant();
        var builder = new StringBuilder(folded.Length);
        var depth = 0;

        foreach (var character in folded)
        {
            // a parenthesised group is dropped whole - it is a provider's disambiguator ("(1997)", "(remake)"),
            // never part of the name people search with
            if (character is '(' or '[')
            {
                depth++;
                builder.Append(' ');
                continue;
            }
            if (character is ')' or ']')
            {
                if (depth > 0) depth--;
                continue;
            }
            if (depth > 0) continue;

            if (char.IsLetterOrDigit(character))
            {
                builder.Append(character);
            }
            else if (character is '\'' or '’')
            {
                // an apostrophe is dropped rather than collapsed to a space, so one catalogue's
                // "Assassin's Creed" and another's "Assassins Creed" tokenize the same way. Spacing it instead
                // produced "assassin s creed", which matched neither spelling.
                continue;
            }
            else
            {
                // "&" and every separator collapse to a single space, so "Rock & Roll", "Rock and Roll" and
                // "Rock: Roll" all tokenize the same way
                builder.Append(character == '&' ? " and " : " ");
            }
        }

        return string.Join(' ', builder.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(token => token != "the"));
    }

    /// <summary>
    /// The title with any parenthesised or bracketed group removed, and nothing else touched - case,
    /// punctuation and accents all preserved, so the result is still a title a provider could hold verbatim.
    /// <para>
    /// <see cref="NormalizeLoose"/> only helps once candidates are in hand; this is for asking the provider in
    /// the first place. RAWG disambiguates a remake by putting the original's year in the title itself
    /// (<c>GoldenEye 007 (1997)</c>, <c>God of War (2018)</c>, <c>Demon's Souls (2020)</c>), and confirmed
    /// against the live IGDB API, querying with that string returns *nothing at all* - neither its exact-name
    /// lookup nor its relevance search finds a thing, so there is no candidate list for a looser comparison to
    /// rescue. Retrying with the bare title is what turns those from a dead end into an ordinary match.
    /// </para>
    /// </summary>
    public static string StripDisambiguator(string title)
    {
        var stripped = new StringBuilder(title.Length);
        var depth = 0;

        foreach (var character in title)
        {
            if (character is '(' or '[') depth++;
            else if (character is ')' or ']') { if (depth > 0) depth--; }
            else if (depth == 0) stripped.Append(character);
        }

        return string.Join(' ', stripped.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    /// <summary>
    /// The title reduced to plain words a provider's own search can parse: diacritics folded, apostrophes
    /// dropped, every other non-alphanumeric run collapsed to a single space. Unlike
    /// <see cref="NormalizeLoose"/> it keeps every word (including "the") and the original casing, because the
    /// result is a *query*, not a matching key.
    /// <para>
    /// It exists because a provider's free-text search is far less forgiving about punctuation than its
    /// catalogue is, confirmed against the live IGDB API: <c>search "NieR:Automata"</c> - a colon glued to the
    /// next letter, exactly how RAWG spells it - returns only "Untitled NieR:Automata Project" and never the
    /// game itself, while <c>search "NieR Automata"</c> returns it as the top hit. The same query is what
    /// rescues a title carrying <c>!</c>, <c>,</c> or an accent.
    /// </para>
    /// <para>
    /// Asking with this form is safe because nothing about *confirmation* loosens: the candidates it brings
    /// back are still checked against the reference's own title with <see cref="LooselyEqual"/> and a
    /// compatible year, and anything but a single match is still left for a human.
    /// </para>
    /// </summary>
    public static string ToProviderQuery(string title)
    {
        var folded = RemoveDiacritics(title);
        var builder = new StringBuilder(folded.Length);

        foreach (var character in folded)
        {
            if (character is '\'' or '’') continue;
            builder.Append(char.IsLetterOrDigit(character) ? character : ' ');
        }

        return string.Join(' ', builder.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    /// <summary>
    /// Whether two provider titles name the same work under <see cref="NormalizeLoose"/>. The one place the
    /// comparison itself is written, so an adoption attempt, the duplicate finder and the Explore exclusion
    /// can't drift apart on what "the same title" means.
    /// </summary>
    public static bool LooselyEqual(string left, string right) =>
        NormalizeLoose(left) == NormalizeLoose(right);

    /// <summary>
    /// Whether <paramref name="candidate"/> contains <paramref name="searched"/> as a whole run of words,
    /// under <see cref="NormalizeLoose"/>. Weaker than <see cref="LooselyEqual"/> on purpose: it answers
    /// "did the searched title actually appear in this result's title", which is what tells a genuine
    /// candidate ("Nevermind (Demo &amp; Outtakes)" for "Nevermind") apart from a result a provider returned
    /// for some other reason entirely.
    /// <para>
    /// It exists because a provider's free-text search parameter matches fields other than the title -
    /// confirmed against the real Discogs API, where <c>q=Discovery&amp;artist=Daft Punk</c> returns
    /// "Live @ Rex Club, Paris" and "MP3 Collection" alongside the album, and <c>q=Sabbath</c> returns
    /// releases whose only occurrence of the word is the artist's name.
    /// See <c>DiscogsClient.SearchAlbumsCoreAsync</c>.
    /// </para>
    /// <para>
    /// The comparison is over whole words rather than raw substrings so a search for "Blue" doesn't keep a
    /// "Blueprint", and a title that normalizes to nothing at all matches everything rather than filtering
    /// the caller's results down to none.
    /// </para>
    /// </summary>
    public static bool LooselyContains(string candidate, string searched)
    {
        var searchedWords = NormalizeLoose(searched).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (searchedWords.Length == 0) return true;

        var candidateWords = NormalizeLoose(candidate).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return Enumerable.Range(0, Math.Max(0, candidateWords.Length - searchedWords.Length + 1))
            .Any(start => candidateWords.Skip(start).Take(searchedWords.Length).SequenceEqual(searchedWords));
    }

    /// <summary>
    /// Strips combining marks so "Pokémon" and "Pokemon" compare equal - the same work spelled by two
    /// catalogues with different opinions about accents.
    /// </summary>
    private static string RemoveDiacritics(string value)
    {
        var decomposed = value.Trim().Normalize(NormalizationForm.FormD);
        var builder = new StringBuilder(decomposed.Length);

        foreach (var character in decomposed.Where(c => CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark))
        {
            builder.Append(character);
        }

        return builder.ToString().Normalize(NormalizationForm.FormC);
    }
}
