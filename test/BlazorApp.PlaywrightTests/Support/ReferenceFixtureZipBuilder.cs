using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.BlazorApp.PlaywrightTests.Support;

/// <summary>
/// Builds a small, synthetic reference-data export zip for <c>ReferenceSmokeTest</c>:
/// a single book, in the same shape <see cref="Keeptrack.WebApi.ReferenceData.ReferenceDataAdminController.Export"/> produces and <c>.Import</c> reads back
/// (see <c>TvTimeFixtureZipBuilder</c> for the same "never use real provider data in tests" spirit, just for reference data instead of a TV Time export).
/// Only the <c>book_reference.json</c> entry is included -
/// the admin controller's import treats a missing entry as an empty list, so there's nothing to gain from also shipping empty tvshow_reference.json/etc. entries.
/// The entry is serialized with default <see cref="JsonSerializerOptions"/> (no camelCase policy),
/// matching exactly what the admin controller itself uses for both export and import -
/// anything else would silently fail to round-trip since the controller applies no naming policy on either side.
/// </summary>
public static class ReferenceFixtureZipBuilder
{
    /// <summary>
    /// A fixed, valid ObjectId for the seeded document, so <c>End2EndFixture</c> can remove exactly this document afterwards.
    /// Re-seeding replaces rather than duplicates because of the fixture's Open Library id, not this one - the import matches on provider ids (see <c>ReferenceDataImportService</c>);
    /// a fixed <c>_id</c> is simply what the first insert lands under.
    /// The value is arbitrary but deliberately recognizable rather than random.
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
