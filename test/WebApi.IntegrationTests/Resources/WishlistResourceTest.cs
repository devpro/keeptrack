using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// The wishlist aggregates several media types into one payload and hydrates each item's cover the same way
/// the individual list endpoints do. Book/video game carry a tenant-owned <c>CustomImageUrl</c> that must
/// override the linked reference's own cover here too - this used to be applied only on the per-type list
/// controllers, never on the wishlist, so a custom cover silently vanished on the wishlist and the shared view.
/// </summary>
public class WishlistResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task Wishlist_AppliesCustomImageUrlOverrideForBooks()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();

        var reference = await referenceRepository.UpsertAsync(new BookReferenceModel
        {
            Title = "Some Reference Title",
            TitleNormalized = "some reference title",
            ExternalIds = new Dictionary<string, string> { ["googlebooks"] = $"gb-{Guid.NewGuid():N}" },
            ImageUrl = "https://example.com/reference-cover.jpg"
        });

        await Authenticate();
        const string customImageUrl = "https://example.com/custom-book-cover.jpg";
        var created = await PostAsync<BookDto>("/api/books", new BookDto
        {
            Title = $"WishlistCustomCoverBook-{Guid.NewGuid():N}",
            Author = "Some Author",
            ReferenceId = reference.Id,
            CustomImageUrl = customImageUrl,
            IsWishlisted = true
        });

        try
        {
            var wishlist = await GetAsync<WishlistDto>("/api/wishlist");
            var item = wishlist.Books.Should().ContainSingle(b => b.Id == created.Id).Subject;
            item.ImageUrl.Should().Be(customImageUrl);
        }
        finally
        {
            await DeleteAsync($"/api/books/{created.Id}");
            var referenceCollection = scope.ServiceProvider.GetRequiredService<IMongoDatabase>().GetCollection<BookReference>("book_reference");
            await referenceCollection.DeleteOneAsync(Builders<BookReference>.Filter.Eq(x => x.Id, reference.Id), TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task Wishlist_AppliesCustomImageUrlOverrideForVideoGames()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IVideoGameReferenceRepository>();

        var reference = await referenceRepository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = "Some Reference Title",
            TitleNormalized = "some reference title",
            ExternalIds = new Dictionary<string, string> { ["rawg"] = $"rawg-{Guid.NewGuid():N}" },
            ImageUrl = "https://example.com/reference-cover.jpg"
        });

        await Authenticate();
        const string customImageUrl = "https://example.com/custom-game-cover.jpg";
        var created = await PostAsync<VideoGameDto>("/api/video-games", new VideoGameDto
        {
            Title = $"WishlistCustomCoverGame-{Guid.NewGuid():N}",
            ReferenceId = reference.Id,
            CustomImageUrl = customImageUrl,
            IsWishlisted = true
        });

        try
        {
            var wishlist = await GetAsync<WishlistDto>("/api/wishlist");
            var item = wishlist.VideoGames.Should().ContainSingle(g => g.Id == created.Id).Subject;
            item.ImageUrl.Should().Be(customImageUrl);
        }
        finally
        {
            await DeleteAsync($"/api/video-games/{created.Id}");
            var referenceCollection = scope.ServiceProvider.GetRequiredService<IMongoDatabase>().GetCollection<VideoGameReference>("videogame_reference");
            await referenceCollection.DeleteOneAsync(Builders<VideoGameReference>.Filter.Eq(x => x.Id, reference.Id), TestContext.Current.CancellationToken);
        }
    }
}
