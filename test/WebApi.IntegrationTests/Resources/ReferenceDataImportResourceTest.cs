using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Bson;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Covers what POST /api/reference-data/import promises against a database that <b>already holds reference
/// data of its own</b> - the case that separates matching by provider id from matching by the <c>_id</c> the
/// export happens to carry, and the one no mocked-repository test can prove: the unique partial indexes on
/// <c>external_ids.*</c> are real, so importing a second copy of a work doesn't produce a duplicate, it
/// produces a failed write.
/// <para>
/// Each test seeds a synthetic reference document through its repository, then uploads a zip in exactly the
/// shape <c>Export</c> produces (same entry names, same default <see cref="JsonSerializerOptions"/> - the
/// controller applies no naming policy on either side, so anything else silently fails to round-trip).
/// </para>
/// </summary>
public class ReferenceDataImportResourceTest(KestrelWebAppFactory<Program> factory) : ResourceTestBase(factory)
{
    [Fact]
    public async Task Import_WhenTheTargetAlreadyHasTheSameProviderId_UpdatesThatDocumentInPlace()
    {
        await Authenticate();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var tmdbId = TestExternalId.New();
        var seeded = await SeedTvShowAsync(repository, "Import Target Show", tmdbId);

        // the same show as the export of another environment would carry it: same TMDB id, a different _id
        var result = await ImportAsync(new ReferenceDataImportPayload
        {
            TvShows = [NewTvShow("Import Source Show", tmdbId, NewObjectId())]
        });

        result.TvShows.Updated.Should().Be(1);
        result.TvShows.Created.Should().Be(0);
        var stored = await repository.FindByExternalIdAsync("tmdb", tmdbId);
        stored.Should().NotBeNull();
        // the target's own _id survives, which is the property every tenant's ReferenceId depends on
        stored.Id.Should().Be(seeded.Id);
        stored.Title.Should().Be("Import Source Show");
        (await repository.FindAllAsync()).Count(s => s.ExternalIds.GetValueOrDefault("tmdb") == tmdbId).Should().Be(1);
    }

    [Fact]
    public async Task Import_WhenTheTargetHasNothingMatching_CreatesTheDocument()
    {
        await Authenticate();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var tmdbId = TestExternalId.New();
        var id = NewObjectId();
        TrackDocument("tvshow_reference", id);

        var result = await ImportAsync(new ReferenceDataImportPayload { TvShows = [NewTvShow("Import New Show", tmdbId, id)] });

        result.TvShows.Created.Should().Be(1);
        result.TvShows.Updated.Should().Be(0);
        (await repository.FindByExternalIdAsync("tmdb", tmdbId)).Should().NotBeNull();
    }

    /// <summary>
    /// An export is one environment's snapshot, and the target legitimately knows things it doesn't: aliases
    /// its own tenants' searches confirmed, and ratings from a provider the exporting environment never
    /// called (an IMDb value costs a metered OMDb call). A replace would throw all of that away.
    /// </summary>
    [Fact]
    public async Task Import_KeepsTheAliasesAndRatingsOnlyTheTargetHas()
    {
        await Authenticate();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
        var tmdbId = TestExternalId.New();
        var seeded = await repository.UpsertAsync(new MovieReferenceModel
        {
            Title = "Import Merge Movie",
            TitleNormalized = "import merge movie",
            Year = 1999,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = tmdbId },
            MatchedAliases = [new ReferenceMatchModel { Title = "locally confirmed alias", Year = 1999 }],
            Ratings = new Dictionary<string, ReferenceRatingModel>
            {
                ["imdb"] = new() { Value = 8.4, Scale = 10, Count = 100 }
            },
            RatingsCheckedAt = new Dictionary<string, DateTime> { ["imdb"] = new(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc) },
            Synopsis = "Known only to the target.",
            ImageUrl = "https://example.invalid/target.jpg"
        });
        TrackDocument("movie_reference", seeded.Id);

        await ImportAsync(new ReferenceDataImportPayload
        {
            Movies =
            [
                new MovieReferenceModel
                {
                    Id = NewObjectId(),
                    Title = "Import Merge Movie",
                    TitleNormalized = "import merge movie",
                    Year = 1999,
                    ExternalIds = new Dictionary<string, string> { ["tmdb"] = tmdbId },
                    Ratings = new Dictionary<string, ReferenceRatingModel> { ["tmdb"] = new() { Value = 7.2, Scale = 10, Count = 5000 } },
                    RatingsCheckedAt = new Dictionary<string, DateTime> { ["imdb"] = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc) }
                }
            ]
        });

        var stored = await repository.FindByExternalIdAsync("tmdb", tmdbId);
        stored.Should().NotBeNull();
        stored.Ratings.Should().ContainKey("imdb").WhoseValue.Value.Should().Be(8.4);
        stored.Ratings.Should().ContainKey("tmdb").WhoseValue.Value.Should().Be(7.2);
        stored.MatchedAliases.Should().Contain(a => a.Title == "locally confirmed alias");
        // an older stamp arriving in an import must never move the re-attempt window backwards
        stored.RatingsCheckedAt["imdb"].Should().Be(new DateTime(2026, 7, 1, 0, 0, 0, DateTimeKind.Utc));
        // the import carried no synopsis/cover, which must not blank what the target already had
        stored.Synopsis.Should().Be("Known only to the target.");
        stored.ImageUrl.Should().Be("https://example.invalid/target.jpg");
    }

    /// <summary>
    /// Cast is stored as a <c>person_reference</c> <c>_id</c>, and that id is local to the database that
    /// minted it. Matching people by their provider id is only half the job: every document citing them has
    /// to be re-pointed at the id the target stores them under, or an imported show's cast references
    /// documents that aren't there.
    /// </summary>
    [Fact]
    public async Task Import_RepointsCastAtTheTargetsOwnPersonDocuments()
    {
        await Authenticate();
        using var scope = Factory.Services.CreateScope();
        var personRepository = scope.ServiceProvider.GetRequiredService<IPersonReferenceRepository>();
        var showRepository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var personTmdbId = TestExternalId.New();
        var showTmdbId = TestExternalId.New();
        var seededPerson = await personRepository.UpsertAsync(new PersonReferenceModel
        {
            Name = "Import Cast Actor",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = personTmdbId }
        });
        TrackDocument("person_reference", seededPerson.Id);
        var exportedPersonId = NewObjectId();
        var exportedShowId = NewObjectId();
        TrackDocument("tvshow_reference", exportedShowId);

        var show = NewTvShow("Import Cast Show", showTmdbId, exportedShowId);
        show.Cast = [new CastMemberModel { PersonReferenceId = exportedPersonId, CharacterName = "Themselves", Order = 0 }];
        await ImportAsync(new ReferenceDataImportPayload
        {
            People =
            [
                new PersonReferenceModel
                {
                    Id = exportedPersonId,
                    Name = "Import Cast Actor",
                    ExternalIds = new Dictionary<string, string> { ["tmdb"] = personTmdbId }
                }
            ],
            TvShows = [show]
        });

        var stored = await showRepository.FindByExternalIdAsync("tmdb", showTmdbId);
        stored.Should().NotBeNull();
        stored.Cast.Should().ContainSingle().Which.PersonReferenceId.Should().Be(seededPerson.Id);
    }

    /// <summary>
    /// Two documents in the target, each holding one of the provider ids the imported document carries -
    /// one work the target recorded twice. Writing both ids onto whichever it matched would hit the unique
    /// partial index and abort the rest of the import (a zip is not a transaction), so the id is left behind
    /// and reported: merging two existing reference documents is an admin decision, not an import's.
    /// </summary>
    [Fact]
    public async Task Import_WhenAnotherDocumentAlreadyClaimsAProviderId_SkipsThatIdAndReportsIt()
    {
        await Authenticate();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var googleId = TestExternalId.New();
        var openLibraryId = TestExternalId.New();
        var viaGoogle = await SeedBookAsync(repository, "Import Conflict Book (Google)", "googlebooks", googleId);
        var viaOpenLibrary = await SeedBookAsync(repository, "Import Conflict Book (Open Library)", "openlibrary", openLibraryId);

        var result = await ImportAsync(new ReferenceDataImportPayload
        {
            Books =
            [
                new BookReferenceModel
                {
                    Id = NewObjectId(),
                    Title = "Import Conflict Book",
                    TitleNormalized = "import conflict book",
                    ExternalIds = new Dictionary<string, string> { ["googlebooks"] = googleId, ["openlibrary"] = openLibraryId }
                }
            ]
        });

        result.SkippedExternalIds.Should().ContainSingle().Which.Should().Be($"openlibrary:{openLibraryId}");
        // both target documents are still there, each keeping the id it held
        (await repository.FindByIdAsync(viaGoogle.Id!))!.ExternalIds["googlebooks"].Should().Be(googleId);
        (await repository.FindByIdAsync(viaOpenLibrary.Id!))!.ExternalIds["openlibrary"].Should().Be(openLibraryId);
    }

    /// <summary>
    /// The matching rule is provider-agnostic - it walks whatever keys a document carries - so every domain
    /// and every provider it can be linked through behaves the same. This pins the ones a single-provider
    /// test would miss: a video game under IGDB (the default that replaced RAWG), an album under Discogs and
    /// a book under Google Books (the default, and the one with no unique index of its own until recently).
    /// </summary>
    [Fact]
    public async Task Import_MatchesEveryDomainThroughItsOwnProvider()
    {
        await Authenticate();
        using var scope = Factory.Services.CreateScope();
        var gameRepository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var albumRepository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var bookRepository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var igdbId = TestExternalId.New();
        var discogsId = TestExternalId.New();
        var googleId = TestExternalId.New();

        var seededGame = await gameRepository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = "Import Target Game",
            TitleNormalized = "import target game",
            ExternalIds = new Dictionary<string, string> { ["igdb"] = igdbId }
        });
        TrackDocument("videogame_reference", seededGame.Id);
        var seededAlbum = await albumRepository.UpsertAsync(new AlbumReferenceModel
        {
            Title = "Import Target Album",
            TitleNormalized = "import target album",
            ExternalIds = new Dictionary<string, string> { ["discogs"] = discogsId }
        });
        TrackDocument("album_reference", seededAlbum.Id);
        var seededBook = await SeedBookAsync(bookRepository, "Import Target Book", "googlebooks", googleId);

        var result = await ImportAsync(new ReferenceDataImportPayload
        {
            VideoGames =
            [
                new VideoGameReferenceModel
                {
                    Id = NewObjectId(),
                    Title = "Import Source Game",
                    TitleNormalized = "import source game",
                    ExternalIds = new Dictionary<string, string> { ["igdb"] = igdbId }
                }
            ],
            Albums =
            [
                new AlbumReferenceModel
                {
                    Id = NewObjectId(),
                    Title = "Import Source Album",
                    TitleNormalized = "import source album",
                    ExternalIds = new Dictionary<string, string> { ["discogs"] = discogsId }
                }
            ],
            Books =
            [
                new BookReferenceModel
                {
                    Id = NewObjectId(),
                    Title = "Import Source Book",
                    TitleNormalized = "import source book",
                    ExternalIds = new Dictionary<string, string> { ["googlebooks"] = googleId }
                }
            ]
        });

        result.VideoGames.Updated.Should().Be(1);
        result.Albums.Updated.Should().Be(1);
        result.Books.Updated.Should().Be(1);
        (await gameRepository.FindByExternalIdAsync("igdb", igdbId))!.Id.Should().Be(seededGame.Id);
        (await albumRepository.FindByExternalIdAsync("discogs", discogsId))!.Id.Should().Be(seededAlbum.Id);
        (await bookRepository.FindByExternalIdAsync("googlebooks", googleId))!.Id.Should().Be(seededBook.Id);
    }

    /// <summary>
    /// A game linked through RAWG that later adopted an IGDB id matches on either key, and the import must
    /// leave it holding both - dropping one would make the next sync pay to re-adopt it.
    /// </summary>
    [Fact]
    public async Task Import_KeepsAProviderIdTheTargetHasAndTheExportDoesNot()
    {
        await Authenticate();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var rawgId = TestExternalId.New();
        var igdbId = TestExternalId.New();
        var seeded = await repository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = "Import Two Provider Game",
            TitleNormalized = "import two provider game",
            ExternalIds = new Dictionary<string, string> { ["rawg"] = rawgId, ["igdb"] = igdbId }
        });
        TrackDocument("videogame_reference", seeded.Id);

        await ImportAsync(new ReferenceDataImportPayload
        {
            VideoGames =
            [
                new VideoGameReferenceModel
                {
                    Id = NewObjectId(),
                    Title = "Import Two Provider Game",
                    TitleNormalized = "import two provider game",
                    ExternalIds = new Dictionary<string, string> { ["igdb"] = igdbId }
                }
            ]
        });

        var stored = await repository.FindByIdAsync(seeded.Id!);
        stored.Should().NotBeNull();
        stored.ExternalIds.Should().Contain(new KeyValuePair<string, string>("rawg", rawgId));
        stored.ExternalIds.Should().Contain(new KeyValuePair<string, string>("igdb", igdbId));
    }

    /// <summary>
    /// The real cross-environment case for video games: an export taken while a game was still only RAWG-linked,
    /// imported into a database that has since adopted IGDB for the same game. It matches on the one id they
    /// share, so nothing duplicates - and the IGDB id and IGDB-sourced ratings survive, because the import only
    /// speaks for what it carries. The descriptive fields it *does* carry (RAWG-era title, synopsis, cover)
    /// deliberately do win: an import is supposed to update the data. What it can't reach through IGDB again is
    /// what has to be protected, and the next sync re-fetches the rest through the default provider anyway.
    /// </summary>
    [Fact]
    public async Task Import_OfARawgOnlyExport_KeepsTheTargetsAdoptedIgdbLinkAndRatings()
    {
        await Authenticate();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var rawgId = TestExternalId.New();
        var igdbId = TestExternalId.New();
        var seeded = await repository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = "Import Adopted Game (IGDB title)",
            TitleNormalized = "import adopted game (igdb title)",
            Year = 2015,
            Synopsis = "Synopsis fetched from IGDB.",
            ImageUrl = "https://images.igdb.invalid/cover.jpg",
            Platforms = ["PC", "PS4"],
            Genres = ["Action"],
            ExternalIds = new Dictionary<string, string> { ["rawg"] = rawgId, ["igdb"] = igdbId },
            Ratings = new Dictionary<string, ReferenceRatingModel>
            {
                ["igdb"] = new() { Value = 91, Scale = 100, Count = 2400 },
                ["igdbcritic"] = new() { Value = 88, Scale = 100, Count = 18 },
                ["rawg"] = new() { Value = 4.1, Scale = 5, Count = 900 }
            },
            LastEnrichedAt = new DateTime(2026, 7, 28, 0, 0, 0, DateTimeKind.Utc)
        });
        TrackDocument("videogame_reference", seeded.Id);

        var result = await ImportAsync(new ReferenceDataImportPayload
        {
            VideoGames =
            [
                new VideoGameReferenceModel
                {
                    Id = NewObjectId(),
                    Title = "Import Adopted Game (RAWG title)",
                    TitleNormalized = "import adopted game (rawg title)",
                    Year = 2015,
                    Synopsis = "Synopsis fetched from RAWG.",
                    ExternalIds = new Dictionary<string, string> { ["rawg"] = rawgId },
                    Ratings = new Dictionary<string, ReferenceRatingModel>
                    {
                        ["rawg"] = new() { Value = 4.4, Scale = 5, Count = 1200 },
                        ["metacritic"] = new() { Value = 84, Scale = 100 }
                    },
                    LastEnrichedAt = new DateTime(2025, 3, 1, 0, 0, 0, DateTimeKind.Utc)
                }
            ]
        });

        result.VideoGames.Updated.Should().Be(1);
        result.SkippedExternalIds.Should().BeEmpty();
        var stored = await repository.FindByIdAsync(seeded.Id!);
        stored.Should().NotBeNull();
        // one document, still under the target's own id, still carrying both provider ids
        (await repository.FindAllAsync()).Count(g => g.ExternalIds.GetValueOrDefault("rawg") == rawgId).Should().Be(1);
        stored.ExternalIds.Should().Contain(new KeyValuePair<string, string>("igdb", igdbId));
        // IGDB's ratings survive an import that never mentions them; the export owns the sources it does carry
        stored.Ratings["igdb"].Value.Should().Be(91);
        stored.Ratings["igdbcritic"].Value.Should().Be(88);
        stored.Ratings["rawg"].Value.Should().Be(4.4);
        stored.Ratings["metacritic"].Value.Should().Be(84);
        // the export's own descriptive data wins where it has any, and the target's is kept where it doesn't
        stored.Title.Should().Be("Import Adopted Game (RAWG title)");
        stored.Synopsis.Should().Be("Synopsis fetched from RAWG.");
        stored.ImageUrl.Should().Be("https://images.igdb.invalid/cover.jpg");
        stored.Platforms.Should().Equal("PC", "PS4");
    }

    [Fact]
    public async Task Import_RunTwice_LeavesOneDocumentAndTheSameId()
    {
        await Authenticate();
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var tmdbId = TestExternalId.New();
        var id = NewObjectId();
        TrackDocument("tvshow_reference", id);
        var payload = new ReferenceDataImportPayload { TvShows = [NewTvShow("Import Twice Show", tmdbId, id)] };

        var first = await ImportAsync(payload);
        var second = await ImportAsync(new ReferenceDataImportPayload { TvShows = [NewTvShow("Import Twice Show", tmdbId, id)] });

        first.TvShows.Created.Should().Be(1);
        second.TvShows.Updated.Should().Be(1);
        var stored = await repository.FindAllAsync();
        stored.Count(s => s.ExternalIds.GetValueOrDefault("tmdb") == tmdbId).Should().Be(1);
    }

    private async Task<ReferenceDataImportResultDto> ImportAsync(ReferenceDataImportPayload payload) =>
        await PostFileAsync<ReferenceDataImportResultDto>(
            "/api/reference-data/import", "file", BuildZip(payload), "keeptrack-reference-data.zip");

    private async Task<TvShowReferenceModel> SeedTvShowAsync(ITvShowReferenceRepository repository, string title, string tmdbId)
    {
        var seeded = await repository.UpsertAsync(NewTvShow(title, tmdbId, id: null));
        TrackDocument("tvshow_reference", seeded.Id);
        return seeded;
    }

    private async Task<BookReferenceModel> SeedBookAsync(IBookReferenceRepository repository, string title, string provider, string externalId)
    {
        var seeded = await repository.UpsertAsync(new BookReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            ExternalIds = new Dictionary<string, string> { [provider] = externalId }
        });
        TrackDocument("book_reference", seeded.Id);
        return seeded;
    }

    private static TvShowReferenceModel NewTvShow(string title, string tmdbId, string? id) => new()
    {
        Id = id,
        Title = title,
        TitleNormalized = title.ToLowerInvariant(),
        Year = 2020,
        ExternalIds = new Dictionary<string, string> { ["tmdb"] = tmdbId }
    };

    private static string NewObjectId() => ObjectId.GenerateNewId().ToString();

    /// <summary>
    /// The same six entry names and the same default serializer options <c>Export</c> writes - the controller
    /// applies no naming policy on either side, so a camelCase zip would deserialize into empty documents.
    /// </summary>
    private static byte[] BuildZip(ReferenceDataImportPayload payload)
    {
        using var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            WriteEntry(archive, "tvshow_reference.json", payload.TvShows);
            WriteEntry(archive, "movie_reference.json", payload.Movies);
            WriteEntry(archive, "person_reference.json", payload.People);
            WriteEntry(archive, "book_reference.json", payload.Books);
            WriteEntry(archive, "videogame_reference.json", payload.VideoGames);
            WriteEntry(archive, "album_reference.json", payload.Albums);
        }

        return buffer.ToArray();
    }

    private static void WriteEntry<T>(ZipArchive archive, string entryName, List<T> value)
    {
        using var entryStream = archive.CreateEntry(entryName, CompressionLevel.Optimal).Open();
        JsonSerializer.Serialize(entryStream, value);
    }
}
