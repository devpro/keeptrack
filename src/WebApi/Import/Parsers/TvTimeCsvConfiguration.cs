using System.Globalization;
using CsvHelper.Configuration;

namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// Shared CsvHelper configuration for every TV Time export file: tolerant of the differing
/// column sets between the several export-generation files this importer reads.
/// </summary>
internal static class TvTimeCsvConfiguration
{
    public static CsvConfiguration Instance { get; } = new(CultureInfo.InvariantCulture)
    {
        PrepareHeaderForMatch = args => args.Header.Trim().ToLowerInvariant()
    };
}
