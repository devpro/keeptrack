using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.BlazorApp.PlaywrightTests.Support;

/// <summary>
/// Builds a small, synthetic reference-data export zip for <c>ReferenceSmokeTest</c>: a single book, in the shape <see cref="Keeptrack.WebApi.ReferenceData.ReferenceDataAdminController.Export"/> produces and <c>.Import</c> reads.
/// Like <c>TvTimeFixtureZipBuilder</c>, it never uses real provider data.
/// Only the <c>book_reference.json</c> entry is included, since the import treats a missing entry as an empty list.
/// The entry is serialized with default <see cref="JsonSerializerOptions"/> (no camelCase), as the controller applies no naming policy on either side, and anything else would silently fail to round-trip.
/// </summary>
public static class ReferenceFixtureZipBuilder
{
    /// <summary>
    /// A fixed, valid ObjectId for the seeded document, so <c>End2EndFixture</c> can remove exactly this document afterwards.
    /// Re-seeding replaces rather than duplicates through the fixture's Open Library id, since the import matches on provider ids (see <c>ReferenceDataImportService</c>), and the first insert lands under this <c>_id</c>.
    /// The value is arbitrary but recognizable rather than random.
    /// </summary>
    public const string ReferenceId = "e2e0e2e0e2e0e2e0e2e0e2e0";

    public const string BookTitle = "The Playwright Chronicles";

    public const string BookAuthor = "Keeptrack E2E Author";

    public const string BookImageUrl = "https://example.invalid/keeptrack-e2e-cover.jpg";

    public static byte[] Build()
    {
        var reference = new BookReferenceModel
        {
            Id = ReferenceId,
            Title = BookTitle,
            TitleNormalized = TitleNormalizer.Normalize(BookTitle),
            Year = 2024,
            Synopsis = "A synthetic book used only by the Playwright e2e smoke suite.",
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = "OL_E2E_TEST" },
            MatchedAliases =
            [
                new ReferenceMatchModel
                {
                    Title = TitleNormalizer.Normalize(BookTitle),
                    Year = 2024,
                    Creator = TitleNormalizer.Normalize(BookAuthor)
                }
            ],
            Genres = ["Testing"],
            ImageUrl = BookImageUrl
        };

        using var zipStream = new MemoryStream();
        using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("book_reference.json");
            using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
            writer.Write(JsonSerializer.Serialize(new List<BookReferenceModel> { reference }));
        }

        return zipStream.ToArray();
    }
}
