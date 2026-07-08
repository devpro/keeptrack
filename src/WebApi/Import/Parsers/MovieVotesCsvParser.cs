using System.Collections.Generic;
using System.IO;
using System.Linq;
using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

public class MovieVoteRecord
{
    [Name("uuid")]
    public required string Uuid { get; set; }

    [Name("movie_name")]
    public required string MovieName { get; set; }
}

/// <summary>
/// Parses TV Time's rating/emotion vote files (ratings-v2-prod-votes.csv, ratings-live-votes.csv,
/// emotions-v2-prod-votes.csv, emotions-live-votes.csv). These files mix movie and episode votes;
/// only rows carrying a movie_name are kept. The <c>uuid</c> here is the vote's own id (used to match
/// the favorite-movies list), NOT a stable movie id - a movie's stable id is its per-movie tracking
/// uuid in tracking-prod-records.csv (see <see cref="MovieTrackingEventRecord"/>). A movie known only
/// from these vote files therefore falls back to a title-derived id at import time.
/// The vote's own emotion/rating code is intentionally not read here: it's an undocumented internal
/// enum, not a linear rating scale.
/// </summary>
public static class MovieVotesCsvParser
{
    public static List<MovieVoteRecord> Parse(Stream csvStream)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        return csv.GetRecords<MovieVoteRecord>()
            .Where(record => !string.IsNullOrWhiteSpace(record.MovieName))
            .ToList();
    }
}
