using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises the reference repositories' <c>FindAllAsync</c> (backs the admin zip export) directly against
/// real MongoDB - every document has to be in it, or the export silently ships an incomplete dataset.
/// The import side is covered end-to-end over HTTP by <see cref="ReferenceDataImportResourceTest"/>, which is
/// where the matching rules live; what stays here is the repository-level guarantee those rules build on.
/// </summary>
public class ReferenceDataExportImportTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task TvShowReferenceRepository_FindAllAsync_IncludesEveryDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Export Test Show {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new TvShowReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() }
        });
        TrackDocument("tvshow_reference", created.Id);

        var all = await repository.FindAllAsync();

        all.Should().Contain(m => m.Id == created.Id && m.Title == title);
    }

    [Fact]
    public async Task TvShowReferenceRepository_ReimportingTheSameExportedDocument_IsANoOp()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowReferenceRepository>();
        var title = $"Reimport Test Show {Guid.NewGuid()}";
        var externalId = TestExternalId.New();

        var created = await repository.UpsertAsync(new TvShowReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = externalId }
        });
        TrackDocument("tvshow_reference", created.Id);

        // re-upserting a document that already carries an id replaces it rather than inserting a second copy
        await repository.UpsertAsync(new TvShowReferenceModel
        {
            Id = created.Id,
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = externalId }
        });

        var all = await repository.FindAllAsync();

        all.Count(m => m.Id == created.Id).Should().Be(1);
    }

    [Fact]
    public async Task MovieReferenceRepository_FindAllAsync_IncludesEveryDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMovieReferenceRepository>();
        var title = $"Export Test Movie {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new MovieReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() }
        });
        TrackDocument("movie_reference", created.Id);

        var all = await repository.FindAllAsync();

        all.Should().Contain(m => m.Id == created.Id && m.Title == title);
    }

    [Fact]
    public async Task PersonReferenceRepository_FindAllAsync_IncludesEveryDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IPersonReferenceRepository>();

        var created = await repository.UpsertAsync(new PersonReferenceModel
        {
            Name = "Export Test Actor",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = TestExternalId.New() }
        });
        TrackDocument("person_reference", created.Id);

        var all = await repository.FindAllAsync();

        all.Should().Contain(p => p.Id == created.Id && p.Name == "Export Test Actor");
    }

    [Fact]
    public async Task BookReferenceRepository_FindAllAsync_IncludesEveryDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var title = $"Export Test Book {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new BookReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = TestExternalId.New() }
        });
        TrackDocument("book_reference", created.Id);

        var all = await repository.FindAllAsync();

        all.Should().Contain(m => m.Id == created.Id && m.Title == title);
    }

    [Fact]
    public async Task VideoGameReferenceRepository_FindAllAsync_IncludesEveryDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();
        var title = $"Export Test Game {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["rawg"] = TestExternalId.New() }
        });
        TrackDocument("videogame_reference", created.Id);

        var all = await repository.FindAllAsync();

        all.Should().Contain(m => m.Id == created.Id && m.Title == title);
    }

    [Fact]
    public async Task AlbumReferenceRepository_FindAllAsync_IncludesEveryDocument()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var title = $"Export Test Album {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new AlbumReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2020,
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() }
        });
        TrackDocument("album_reference", created.Id);

        var all = await repository.FindAllAsync();

        all.Should().Contain(m => m.Id == created.Id && m.Title == title);
    }
}
