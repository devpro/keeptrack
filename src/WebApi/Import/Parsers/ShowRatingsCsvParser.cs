using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Keeptrack.WebApi.Import.Parsers;

public class ShowRatingRecord
{
    [Name("tv_show_id")]
    public required string TvShowId { get; set; }

    [Name("rating")]
    public required float Rating { get; set; }
}

/// <summary>
/// Parses TV Time's tv_show_rate.csv: a clean 0-5 rating per show.
/// </summary>
public static class ShowRatingsCsvParser
{
    public static List<ShowRatingRecord> Parse(Stream csvStream)
    {
        using var reader = new StreamReader(csvStream);
        using var csv = new CsvReader(reader, TvTimeCsvConfiguration.Instance);
        return csv.GetRecords<ShowRatingRecord>().ToList();
    }
}
