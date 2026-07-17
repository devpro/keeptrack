using System;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises <c>MongoDbRepositoryBase.FindAllAsync</c>'s sort translation against real MongoDB - the
/// interesting behaviors (the title sort's case-insensitive collation, descending-sort null placement,
/// the newest-first default from _id ordering) are server-side semantics a mocked repository can never
/// prove. One entity type suffices: the sort switch and collation live once in the shared base, and
/// Book covers both overridable sort fields (title and rating). Each test run uses its own random
/// owner id, so parallel runs and other tests' data can't interfere with the ordering assertions.
/// </summary>
public class ListSortingRepositoryTest(KestrelWebAppFactory<Program> factory) : IClassFixture<KestrelWebAppFactory<Program>>
{
    [Fact]
    public async Task FindAllAsync_SortsByDefault_TitleAndRating()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookRepository>();
        var ownerId = $"sort-test-{Guid.NewGuid():N}";

        // creation order deliberately differs from every sorted order; "apple" (lowercase) between
        // "Banana" and "Cherry" proves the title collation, the null rating proves nulls sort last
        var created = new[]
        {
            await repository.CreateAsync(NewBook(ownerId, "Banana", rating: 2f)),
            await repository.CreateAsync(NewBook(ownerId, "apple", rating: null)),
            await repository.CreateAsync(NewBook(ownerId, "Cherry", rating: 4.5f)),
        };

        try
        {
            var byDefault = await repository.FindAllAsync(ownerId, 1, 10, null, NewBook(ownerId, ""));
            byDefault.Items.Select(b => b.Title).Should().Equal(["Cherry", "apple", "Banana"],
                "the default order is newest first");

            var byTitle = await repository.FindAllAsync(ownerId, 1, 10, null, NewBook(ownerId, ""), ListSort.Title);
            byTitle.Items.Select(b => b.Title).Should().Equal(["apple", "Banana", "Cherry"],
                "the title sort is case-insensitive, not byte order (which would put every uppercase title first)");

            var byRating = await repository.FindAllAsync(ownerId, 1, 10, null, NewBook(ownerId, ""), ListSort.Rating);
            byRating.Items.Select(b => b.Title).Should().Equal(["Cherry", "Banana", "apple"],
                "the rating sort is best-first with unrated items last");

            var byUnknownKey = await repository.FindAllAsync(ownerId, 1, 10, null, NewBook(ownerId, ""), "nonsense");
            byUnknownKey.Items.Select(b => b.Title).Should().Equal(["Cherry", "apple", "Banana"],
                "an unknown sort key falls back to the newest-first default rather than erroring");
        }
        finally
        {
            foreach (var book in created)
            {
                await repository.DeleteAsync(book.Id!, ownerId);
            }
        }
    }

    [Fact]
    public async Task FindAllAsync_KeepsTheSortStable_AcrossPages()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookRepository>();
        var ownerId = $"sort-test-{Guid.NewGuid():N}";

        var created = new BookModel[5];
        for (var i = 0; i < created.Length; i++)
        {
            created[i] = await repository.CreateAsync(NewBook(ownerId, $"Book {i:D2}"));
        }

        try
        {
            // paging through a sorted list must partition it exactly: no duplicates, no drops - the
            // guarantee an unsorted skip/limit read never had
            var page1 = await repository.FindAllAsync(ownerId, 1, 2, null, NewBook(ownerId, ""), ListSort.Title);
            var page2 = await repository.FindAllAsync(ownerId, 2, 2, null, NewBook(ownerId, ""), ListSort.Title);
            var page3 = await repository.FindAllAsync(ownerId, 3, 2, null, NewBook(ownerId, ""), ListSort.Title);

            page1.Items.Concat(page2.Items).Concat(page3.Items).Select(b => b.Title)
                .Should().Equal("Book 00", "Book 01", "Book 02", "Book 03", "Book 04");
        }
        finally
        {
            foreach (var book in created)
            {
                await repository.DeleteAsync(book.Id!, ownerId);
            }
        }
    }

    private static BookModel NewBook(string ownerId, string title, float? rating = null) => new()
    {
        OwnerId = ownerId,
        Title = title,
        Author = "Sort Test Author",
        Rating = rating,
    };
}
