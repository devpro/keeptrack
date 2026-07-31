using System;
using System.Collections.Generic;
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
/// Exercises <see cref="IAlbumReferenceRepository.FindByTitleYearAsync"/>/<see cref="IAlbumReferenceRepository.FindByTitleAsync"/>
/// against real MongoDB - same <c>ElemMatch</c>/<c>MatchedAliases</c> shape already verified for
/// <see cref="ITvShowReferenceRepository"/> (see <c>TvShowReferenceRepositoryTest</c>), applied to albums.
/// </summary>
public class AlbumReferenceRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindByTitleYearAsync_MatchesAnAliasWhoseConfirmedYearDiffersFromTheDocumentsOwnCanonicalYear()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var alternateTitle = $"Alternate Album Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new AlbumReferenceModel
        {
            Title = "Canonical Album Title",
            TitleNormalized = "canonical album title",
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2004, Creator = "some artist" }]
        });

        var found = await repository.FindByTitleYearAsync(alternateTitle, 2004, "Some Artist");

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    [Fact]
    public async Task FindByTitleAsync_MatchesAnAlternateTitle_IgnoringYear()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var alternateTitle = $"Alternate Album Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new AlbumReferenceModel
        {
            Title = "Canonical Album Title",
            TitleNormalized = "canonical album title",
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2005, Creator = "some artist" }]
        });

        var found = await repository.FindByTitleAsync(alternateTitle, "Some Artist");

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    [Fact]
    public async Task UpsertAsync_AlwaysIncludesTheCanonicalTitleAndYearInMatchedAliases_EvenIfTheCallerForgot()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var title = $"Canonical Only Album Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new AlbumReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2010,
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() }
        });

        // this safety-net alias has no Creator (the model only carries ArtistReferenceId, not
        // denormalized text - see AlbumReferenceRepository.UpsertAsync), so it's unreachable via the
        // creator-required FindByTitleAsync/FindByTitleYearAsync; assert on the stored alias directly.
        var found = await repository.FindByIdAsync(created.Id!);

        found.Should().NotBeNull();
        found!.MatchedAliases.Should().ContainSingle(m => string.Equals(m.Title, title, StringComparison.OrdinalIgnoreCase) && m.Year == 2010);
    }

    private async Task<AlbumReferenceModel> CreateReferenceAsync(IAlbumReferenceRepository repository, AlbumReferenceModel model)
    {
        var created = await repository.UpsertAsync(model);
        TrackDocument("album_reference", created.Id);
        return created;
    }
}
