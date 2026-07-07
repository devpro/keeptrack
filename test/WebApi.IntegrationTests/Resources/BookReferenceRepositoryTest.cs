using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Microsoft.Extensions.DependencyInjection;
using MongoDB.Driver;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// Exercises <see cref="IBookReferenceRepository.FindByTitleYearAsync"/>/<see cref="IBookReferenceRepository.FindByTitleAsync"/>
/// against real MongoDB - same <c>ElemMatch</c>/<c>MatchedAliases</c> shape already verified for
/// <see cref="ITvShowReferenceRepository"/> (see <c>TvShowReferenceRepositoryTest</c>), applied to books.
/// </summary>
public class BookReferenceRepositoryTest(KestrelWebAppFactory<Program> factory) : IClassFixture<KestrelWebAppFactory<Program>>
{
    [Fact]
    public async Task FindByTitleYearAsync_MatchesAnAliasWhoseConfirmedYearDiffersFromTheDocumentsOwnCanonicalYear()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var alternateTitle = $"Alternate Book Title {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new BookReferenceModel
        {
            Title = "Canonical Book Title", TitleNormalized = "canonical book title", Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = "OL1W" },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2004, Creator = "some author" }]
        });

        try
        {
            var found = await repository.FindByTitleYearAsync(alternateTitle, 2004, "Some Author");

            found.Should().NotBeNull();
            found!.Id.Should().Be(created.Id);
        }
        finally
        {
            await DeleteAsync(scope, created.Id!);
        }
    }

    [Fact]
    public async Task FindByTitleAsync_MatchesAnAlternateTitle_IgnoringYear()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var alternateTitle = $"Alternate Book Title {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new BookReferenceModel
        {
            Title = "Canonical Book Title", TitleNormalized = "canonical book title", Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = "OL1W" },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2005, Creator = "some author" }]
        });

        try
        {
            var found = await repository.FindByTitleAsync(alternateTitle, "Some Author");

            found.Should().NotBeNull();
            found!.Id.Should().Be(created.Id);
        }
        finally
        {
            await DeleteAsync(scope, created.Id!);
        }
    }

    [Fact]
    public async Task UpsertAsync_AlwaysIncludesTheCanonicalTitleAndYearInMatchedAliases_EvenIfTheCallerForgot()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var title = $"Canonical Only Book Title {Guid.NewGuid()}";

        var created = await repository.UpsertAsync(new BookReferenceModel
        {
            Title = title, TitleNormalized = title.ToLowerInvariant(), Year = 2010, ExternalIds = new Dictionary<string, string> { ["openlibrary"] = "OL1W" }
        });

        try
        {
            // this safety-net alias has no Creator (the model only carries AuthorReferenceId, not
            // denormalized text - see BookReferenceRepository.UpsertAsync), so it's unreachable via the
            // creator-required FindByTitleAsync/FindByTitleYearAsync; assert on the stored alias directly.
            var found = await repository.FindByIdAsync(created.Id!);

            found.Should().NotBeNull();
            found!.MatchedAliases.Should().ContainSingle(m => m.Title == title.ToLowerInvariant() && m.Year == 2010);
        }
        finally
        {
            await DeleteAsync(scope, created.Id!);
        }
    }

    private static async Task DeleteAsync(IServiceScope scope, string id)
    {
        var collection = scope.ServiceProvider.GetRequiredService<IMongoDatabase>().GetCollection<BookReference>("book_reference");
        await collection.DeleteOneAsync(Builders<BookReference>.Filter.Eq(x => x.Id, id), TestContext.Current.CancellationToken);
    }
}
