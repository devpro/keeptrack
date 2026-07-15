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
public class BookUnresolvedQueueTest(KestrelWebAppFactory<Program> factory) : IClassFixture<KestrelWebAppFactory<Program>>
{
    [Fact]
    public async Task FindDistinctUnresolvedTitleYearsAsync_CarriesATenantsAuthorAsTheCreator()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookRepository>();
        var title = $"Unresolved Queue Test Book {Guid.NewGuid()}";
        const string author = "Unresolved Queue Test Author";

        var bookA = await repository.CreateAsync(new BookModel { OwnerId = "unresolved-book-tenant-a", Title = title, Author = author, Year = 2003 });
        var bookB = await repository.CreateAsync(new BookModel { OwnerId = "unresolved-book-tenant-b", Title = title, Author = author, Year = 2003 });

        try
        {
            var unresolved = await repository.FindDistinctUnresolvedTitleYearsAsync();

            // both unlinked copies collapse into one queue entry, and it carries an author for search prefill
            unresolved.Should().ContainSingle(p => p.Title == title && p.Year == 2003)
                .Which.Creator.Should().Be(author);
        }
        finally
        {
            await repository.DeleteAsync(bookA.Id!, "unresolved-book-tenant-a");
            await repository.DeleteAsync(bookB.Id!, "unresolved-book-tenant-b");
        }
    }
}
