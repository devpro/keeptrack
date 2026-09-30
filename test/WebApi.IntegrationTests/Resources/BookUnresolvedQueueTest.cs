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
/// Exercises <see cref="IBookRepository.FindDistinctUnresolvedTitleYearsAsync"/>'s creator dimension
/// against real MongoDB - the $group + $first accumulator translation is exactly the kind of driver-level
/// behavior a mocked unit test can never validate (same rationale as <see cref="TvShowReferenceLinkingTest"/>).
/// </summary>
public class BookUnresolvedQueueTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindDistinctUnresolvedTitleYearsAsync_CarriesATenantsAuthorAsTheCreator()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookRepository>();
        var title = $"Unresolved Queue Test Book {Guid.NewGuid()}";
        const string author = "Unresolved Queue Test Author";

        await CreateBookAsync(repository, new BookModel { OwnerId = "unresolved-book-tenant-a", Title = title, Author = author, Year = 2003 });
        await CreateBookAsync(repository, new BookModel { OwnerId = "unresolved-book-tenant-b", Title = title, Author = author, Year = 2003 });

        var unresolved = await repository.FindDistinctUnresolvedTitleYearsAsync();

        // both unlinked copies collapse into one queue entry, and it carries an author for search prefill
        unresolved.Should().ContainSingle(p => p.Title == title && p.Year == 2003)
            .Which.Creator.Should().Be(author);
    }

    /// <summary>
    /// Same search-prefill role as Creator, just for ISBN - regression: the admin unresolved-queue page
    /// used to always force its ISBN search field back to null on selecting an item, discarding a tenant's
    /// own already-recorded ISBN instead of prefilling with it.
    /// </summary>
    [Fact]
    public async Task FindDistinctUnresolvedTitleYearsAsync_CarriesATenantsIsbn()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookRepository>();
        var title = $"Unresolved Queue Isbn Test Book {Guid.NewGuid()}";
        const string isbn = "9780000000042";

        await CreateBookAsync(repository, new BookModel { OwnerId = "unresolved-book-isbn-tenant", Title = title, Author = "Some Author", Year = 2003, Isbn = isbn });

        var unresolved = await repository.FindDistinctUnresolvedTitleYearsAsync();

        unresolved.Should().ContainSingle(p => p.Title == title && p.Year == 2003)
            .Which.Isbn.Should().Be(isbn);
    }

    private async Task<BookModel> CreateBookAsync(IBookRepository repository, BookModel book)
    {
        var created = await repository.CreateAsync(book);
        TrackCleanup(() => repository.DeleteAsync(created.Id!, book.OwnerId));
        return created;
    }
}
