using System.Collections.Generic;
using System.IO;
using System.Linq;
using CsvHelper;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Reads every imported CSV file, store exports and TV Time files alike, with one dialect.
/// Headers match ignoring case and surrounding whitespace, and a byte order mark is honored, both CsvHelper defaults.
/// </summary>
public static class ImportCsv
{
    /// <summary>
    /// The separator is pinned, since CsvHelper otherwise detects it from the first lines, and a title holding semicolons would split.
    /// </summary>
    private static readonly CsvReaderOptions s_options = new() { Separator = ',' };

    public static CsvReader Open(Stream csvStream) => CsvReader.Create(csvStream, s_options);

    /// <summary>
    /// Throws when the header lacks a column that <typeparamref name="T"/> requires, rather than reading it as empty.
    /// </summary>
    public static List<T> ReadRecords<T>(Stream csvStream)
    {
        using var csv = Open(csvStream);
        return csv.GetRecords<T>().ToList();
    }
}
