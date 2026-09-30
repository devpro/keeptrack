using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// An admin's album link reaches only the unlinked albums matching the title, the artist and the year it was made with, since an album is its title and artist.
/// </summary>
public class AlbumReferenceLinkingTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task AnAdminsLink_ReachesOnlyTheAlbumsByTheArtistItNames_FromTheSameYear()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IAlbumRepository>();
        var title = $"Album Linking Test {Guid.NewGuid():N}";
        const string artist = "Album Linking Test Artist";

        var sameArtist = await CreateAlbumAsync(repository, "album-link-tenant-a", title, 2000, artist);
        var sameArtistOtherCase = await CreateAlbumAsync(repository, "album-link-tenant-b", title.ToUpperInvariant(), 2000, artist.ToUpperInvariant());
        var otherArtist = await CreateAlbumAsync(repository, "album-link-tenant-c", title, 2000, "Another Artist");
        var otherYear = await CreateAlbumAsync(repository, "album-link-tenant-d", title, 2001, artist);

        var linked = await repository.SetReferenceLinkAsync(ReferenceLinkTarget.Matching(title, 2000, artist), "reference-1", title);

        linked.Should().Be(2);
        (await ReadLinkAsync(repository, sameArtist)).Should().Be("reference-1");
        (await ReadLinkAsync(repository, sameArtistOtherCase)).Should().Be("reference-1");
        (await ReadLinkAsync(repository, otherArtist)).Should().BeNullOrEmpty("another artist's album of that name is another album");
        (await ReadLinkAsync(repository, otherYear)).Should().BeNullOrEmpty("the admin linked with a year, so only that year's albums are reached");
    }

    private async Task<AlbumModel> CreateAlbumAsync(IAlbumRepository repository, string ownerId, string title, int year, string artist)
    {
        var created = await repository.CreateAsync(new AlbumModel { OwnerId = ownerId, Title = title, Year = year, Artist = artist });
        TrackCleanup(() => repository.DeleteAsync(created.Id!, ownerId));
        return created;
    }

    private static async Task<string?> ReadLinkAsync(IAlbumRepository repository, AlbumModel album) =>
        (await repository.FindOneAsync(album.Id!, album.OwnerId, TestContext.Current.CancellationToken))?.ReferenceId;
}
