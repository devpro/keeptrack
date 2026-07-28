using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Testing.Shared.Firebase;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// End-to-end share lifecycle against the live API. The recipient is matched by account email, so the single
/// test account self-shares (as the Playwright smoke test does). Self-share means the recipient already owns
/// everything shared, which is exactly the dedup path: reads flag the items as already-in-collection and a
/// copy returns the existing item instead of duplicating. A grant to a different email is invisible to others.
/// </summary>
public class ShareResourceTest(KestrelWebAppFactory<Program> factory)
    : ResourceTestBase(factory)
{
    [Fact]
    public async Task ShareEndpoints_RequireAuthentication()
    {
        await GetAsync("/api/shares", HttpStatusCode.Unauthorized);
        await GetAsync("/api/shared-with-me", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task MediaShare_IsReadableWithFilters_AndAddIsDedupSafe_ThenRevocable()
    {
        await Authenticate();
        var ownEmail = FirebaseConfiguration.Username;
        var tag = Guid.NewGuid().ToString("N");

        var favourite = await PostAsync<MovieDto>("/api/movies", new MovieDto { Title = $"ShareFav-{tag}", Year = 1999, Rating = 5, IsFavorite = true });
        var plain = await PostAsync<MovieDto>("/api/movies", new MovieDto { Title = $"SharePlain-{tag}", Year = 2001, Rating = 2 });

        var share = await PostAsync<CreateShareRequestDto, ShareDto>("/api/shares", new CreateShareRequestDto
        {
            RecipientEmail = ownEmail,
            IncludedCategories = [ShareCategory.Movies],
            Label = "Myself"
        });

        try
        {
            // owner sees their own grant; recipient (self) sees the shared collection
            (await GetAsync<List<ShareDto>>("/api/shares")).Should().Contain(s => s.Id == share.Id && s.Label == "Myself");
            (await GetAsync<List<SharedCollectionSummaryDto>>("/api/shared-with-me"))
                .Should().Contain(s => s.ShareId == share.Id && s.IncludedCategories.Contains(ShareCategory.Movies));

            // read the shared movies, searching to isolate this test's items; both are already-in-collection (self-share)
            var page = await GetAsync<SharedCategoryPageDto<MovieDto>>($"/api/shared-with-me/{share.Id}/movies?search={tag}&sort=rating");
            page.Items.Should().Contain(m => m.Id == favourite.Id).And.Contain(m => m.Id == plain.Id);
            page.AlreadyInCollectionIds.Should().Contain(favourite.Id!).And.Contain(plain.Id!);

            // the favourites filter narrows to the sharer's favourite only
            var favPage = await GetAsync<SharedCategoryPageDto<MovieDto>>($"/api/shared-with-me/{share.Id}/movies?search={tag}&IsFavorite=true");
            favPage.Items.Should().Contain(m => m.Id == favourite.Id).And.NotContain(m => m.Id == plain.Id);

            // adding an item the recipient already owns is dedup-safe: no duplicate, returns the existing item
            var copy = await PostAsync<object, CopyResultDto<MovieDto>>($"/api/shared-with-me/{share.Id}/movies/{favourite.Id}/copy", new { }, HttpStatusCode.OK);
            copy.AlreadyInCollection.Should().BeTrue();
            copy.Item.Id.Should().Be(favourite.Id);

            // a category not in scope is an indistinguishable 404
            await GetAsync($"/api/shared-with-me/{share.Id}/tv-shows", HttpStatusCode.NotFound);

            // revoking removes access
            await DeleteAsync($"/api/shares/{share.Id}");
            await GetAsync($"/api/shared-with-me/{share.Id}/movies", HttpStatusCode.NotFound);
            (await GetAsync<List<SharedCollectionSummaryDto>>("/api/shared-with-me")).Should().NotContain(s => s.ShareId == share.Id);
        }
        finally
        {
            await DeleteAsync($"/api/movies/{favourite.Id}");
            await DeleteAsync($"/api/movies/{plain.Id}");
            await DeleteAsync($"/api/shares/{share.Id}");
        }
    }

    [Fact]
    public async Task ShareToADifferentEmail_IsNotVisibleToOthers()
    {
        await Authenticate();

        var share = await PostAsync<CreateShareRequestDto, ShareDto>("/api/shares", new CreateShareRequestDto
        {
            RecipientEmail = $"not-me-{Guid.NewGuid():N}@example.com",
            IncludedCategories = [ShareCategory.Movies]
        });

        try
        {
            (await GetAsync<List<SharedCollectionSummaryDto>>("/api/shared-with-me")).Should().NotContain(s => s.ShareId == share.Id);
            await GetAsync($"/api/shared-with-me/{share.Id}/movies", HttpStatusCode.NotFound);
        }
        finally
        {
            await DeleteAsync($"/api/shares/{share.Id}");
        }
    }
}
