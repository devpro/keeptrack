using CsvHelper;
using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.Import.Parsers;

[CsvRecord]
public partial class ShowRatingRecord
{
    [CsvColumn("tv_show_id")]
    public required string TvShowId { get; set; }

    [CsvColumn("rating")]
    public required float Rating { get; set; }
}

/// <summary>
/// Parses TV Time's tv_show_rate.csv: a clean 0-5 rating per show.
/// </summary>
public static class ShowRatingsCsvParser
{
    public static List<ShowRatingRecord> Parse(Stream csvStream)
    {
        return ImportCsv.ReadRecords<ShowRatingRecord>(csvStream);
    }
}
