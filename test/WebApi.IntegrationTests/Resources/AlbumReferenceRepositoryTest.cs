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
/// Exercises <see cref="IAlbumReferenceRepository.FindByTitleCreatorAsync"/> against real MongoDB - the same <c>ElemMatch</c>/<c>MatchedAliases</c> shape already verified for <see cref="ITvShowReferenceRepository"/> (see <c>TvShowReferenceRepositoryTest</c>), keyed the way an album is identified: title plus artist, with no year anywhere in the key.
/// </summary>
public class AlbumReferenceRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindByTitleCreatorAsync_MatchesAnAlternateTitle_NotJustTheCanonicalOne()
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
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Creator = "some artist" }]
        });

        var found = await repository.FindByTitleCreatorAsync(alternateTitle.ToUpperInvariant(), "Some Artist");

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    /// <summary>
    /// A release is reissued, remastered and repressed under as many years as there are pressings, so the year can never narrow this lookup - an alias written years ago still has to answer today's tenant.
    /// </summary>
    [Fact]
    public async Task FindByTitleCreatorAsync_MatchesAnAliasThatStillCarriesAYear_FromBeforeAliasesDroppedIt()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var title = $"Legacy Alias Album {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new AlbumReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = title.ToLowerInvariant(), Year = 1998, Creator = "some artist" }]
        });

        var found = await repository.FindByTitleCreatorAsync(title, "Some Artist");

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    [Fact]
    public async Task FindByTitleCreatorAsync_MatchesNothing_WhenTheArtistIsNotTheOneTheAliasWasConfirmedUnder()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IAlbumReferenceRepository>();
        var title = $"Shared Album Title {Guid.NewGuid()}";

        await CreateReferenceAsync(repository, new AlbumReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            ExternalIds = new Dictionary<string, string> { ["discogs"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = title.ToLowerInvariant(), Creator = "some artist" }]
        });

        var found = await repository.FindByTitleCreatorAsync(title, "Another Artist");

        found.Should().BeNull();
    }

    /// <summary>
    /// A reference document carries its artist as a <see cref="AlbumReferenceModel.ArtistReferenceId"/>, never as text, so the repository has nothing to build a complete alias from - and a creator-less one is exactly the half-key this collection must never hold, since it would answer for every artist at once.
    /// </summary>
    [Fact]
    public async Task UpsertAsync_AddsNoCanonicalAlias_BecauseItCannotKnowTheArtist()
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

        var found = await repository.FindByIdAsync(created.Id!);

        found.Should().NotBeNull();
        found!.MatchedAliases.Should().BeEmpty();
    }

    private async Task<AlbumReferenceModel> CreateReferenceAsync(IAlbumReferenceRepository repository, AlbumReferenceModel model)
    {
        var created = await repository.UpsertAsync(model);
        TrackDocument("album_reference", created.Id);
        return created;
    }
}
