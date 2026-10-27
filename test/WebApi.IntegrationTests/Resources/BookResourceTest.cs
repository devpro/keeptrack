using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Bogus;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

public class BookResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    private const string ResourceEndpoint = "api/books";

    [Fact]
    public async Task BookResourceFullCycle_IsOk()
    {
        await GetAsync($"/{ResourceEndpoint}", HttpStatusCode.Unauthorized);

        await Authenticate();

        var input = new Faker<BookDto>()
            .Rules((f, o) =>
            {
                o.Author = f.Random.AlphaNumeric(8);
                o.Title = f.Random.AlphaNumeric(14);
                // Round-trips Language, CustomImageUrl and Isbn through the real Mapperly mappers and MongoDB, plain scalars,
                // since only a real integration test catches a missed [BsonElement] or mapper ignore.
                o.Language = f.Random.AlphaNumeric(3);
                o.CustomImageUrl = f.Internet.Url();
                o.Isbn = f.Random.Replace("##########");
            })
            .Generate();
        var created = await CreateAsync($"/{ResourceEndpoint}", input);
        created.Id.Should().NotBeNullOrEmpty();

        created.Title = "New shiny title";
        await PutAsync($"/{ResourceEndpoint}/{created.Id}", created);

        var updated = await GetAsync<BookDto>($"/{ResourceEndpoint}/{created.Id}");
        updated.Should().BeEquivalentTo(created, x => x.Excluding(item => item.FirstReadAt)); // issue with DateTime and MongoDB

        var finalItems = await GetAsync<PagedResult<BookDto>>($"/{ResourceEndpoint}");
        var firstItem = finalItems.Items.FirstOrDefault(x => x.Id == updated.Id);
        firstItem.Should().NotBeNull();
        firstItem.Title.Should().Be(updated.Title);
    }

    [Fact]
    public async Task BookResourceOwnedAndWishlistedFilters_OnlyReturnMatchingItems_IsOk()
    {
        await Authenticate();

        var uniqueTitle = $"OwnedWishlistTarget-{Guid.NewGuid():N}";
        var input = new Faker<BookDto>()
            .Rules((f, o) =>
            {
                o.Author = f.Random.AlphaNumeric(8);
                o.Title = uniqueTitle;
                // "owned" is derived from having at least one owned version, not a stored flag
                o.OwnedVersions = [new OwnedVersionDto()];
                o.IsWishlisted = true;
            })
            .Generate();
        var created = await CreateAsync($"/{ResourceEndpoint}", input);

        var owned = await GetAsync<PagedResult<BookDto>>($"/{ResourceEndpoint}?IsOwned=true&search={uniqueTitle}");
        owned.Items.Should().ContainSingle(b => b.Id == created.Id);

        // the WishlistController filter probe, not a list-page UI filter, still real API behaviour
        var wishlisted = await GetAsync<PagedResult<BookDto>>($"/{ResourceEndpoint}?IsWishlisted=true&search={uniqueTitle}");
        wishlisted.Items.Should().ContainSingle(b => b.Id == created.Id);
    }

    /// <summary>
    /// <c>BookController.OnListMappedAsync</c> applies <see cref="BookDto.CustomImageUrl"/> over the linked reference's cover on every list read,
    /// beside the generic <see cref="IReferenceLinkedDto"/> image hydration.
    /// </summary>
    [Fact]
    public async Task BookResourceList_CustomImageUrlOverridesTheLinkedReferencesCover()
    {
        using var scope = Factory.Services.CreateScope();
        var referenceRepository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var uniqueTitle = $"CustomImageOverrideTarget-{Guid.NewGuid():N}";

        var reference = await referenceRepository.UpsertAsync(new BookReferenceModel
        {
            Title = "Some Reference Title",
            TitleNormalized = "some reference title",
            ExternalIds = new Dictionary<string, string> { ["googlebooks"] = TestExternalId.New() },
            ImageUrl = "https://example.com/reference-cover.jpg"
        });
        TrackDocument("book_reference", reference.Id);

        await Authenticate();
        const string customImageUrl = "https://example.com/custom-cover.jpg";
        var created = await CreateAsync($"/{ResourceEndpoint}", new BookDto
        {
            Title = uniqueTitle,
            Author = "Some Author",
            ReferenceId = reference.Id,
            CustomImageUrl = customImageUrl
        });

        var list = await GetAsync<PagedResult<BookDto>>($"/{ResourceEndpoint}?search={uniqueTitle}");
        var item = list.Items.Should().ContainSingle(b => b.Id == created.Id).Subject;
        item.ImageUrl.Should().Be(customImageUrl);
    }
}
