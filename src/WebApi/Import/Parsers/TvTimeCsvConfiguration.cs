using System.Globalization;
using CsvHelper.Configuration;

namespace Keeptrack.WebApi.Import.Parsers;

/// <summary>
/// Shared CsvHelper configuration for every TV Time file, tolerating the differing column sets of the export's generations of files.
/// </summary>
internal static class TvTimeCsvConfiguration
{
    public static CsvConfiguration Instance { get; } = new(CultureInfo.InvariantCulture)
    {
        PrepareHeaderForMatch = args => args.Header.Trim().ToLowerInvariant()
    };
}
