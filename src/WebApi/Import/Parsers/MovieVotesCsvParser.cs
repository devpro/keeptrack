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
/// Parses TV Time's rating/emotion vote files (ratings-v2-prod-votes.csv, ratings-live-votes.csv, emotions-v2-prod-votes.csv, emotions-live-votes.csv).
/// These files mix movie and episode votes; only rows carrying a movie_name are kept.
/// The <c>uuid</c> is the vote's own id, matching the favorite movies list, not a stable movie id,
/// which is the tracking uuid of tracking-prod-records.csv (see <see cref="MovieTrackingEventRecord"/>).
/// A movie known only from these files therefore gets a title-derived id.
/// The emotion or rating code is not read, being an undocumented internal enum rather than a linear scale.
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
