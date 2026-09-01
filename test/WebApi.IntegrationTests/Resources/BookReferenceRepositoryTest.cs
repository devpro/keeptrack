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
/// Exercises <see cref="IBookReferenceRepository.FindByTitleYearAsync"/>/<see cref="IBookReferenceRepository.FindByTitleAsync"/>
/// against real MongoDB - same <c>ElemMatch</c>/<c>MatchedAliases</c> shape already verified for
/// <see cref="ITvShowReferenceRepository"/> (see <c>TvShowReferenceRepositoryTest</c>), applied to books.
/// </summary>
public class BookReferenceRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task FindByTitleYearAsync_MatchesAnAliasWhoseConfirmedYearDiffersFromTheDocumentsOwnCanonicalYear()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var alternateTitle = $"Alternate Book Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new BookReferenceModel
        {
            Title = "Canonical Book Title",
            TitleNormalized = "canonical book title",
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2004, Creator = "some author" }]
        });

        var found = await repository.FindByTitleYearAsync(alternateTitle, 2004, "Some Author");

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    [Fact]
    public async Task FindByTitleAsync_MatchesAnAlternateTitle_IgnoringYear()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var alternateTitle = $"Alternate Book Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new BookReferenceModel
        {
            Title = "Canonical Book Title",
            TitleNormalized = "canonical book title",
            Year = 2005,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = alternateTitle.ToLowerInvariant(), Year = 2005, Creator = "some author" }]
        });

        var found = await repository.FindByTitleAsync(alternateTitle, "Some Author");

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    /// <summary>
    /// <see cref="BookReferenceModel.ExternalIds"/> can carry more than one provider's id at once (e.g. a
    /// reference first linked via Open Library, then also confirmed via BnF for a different tenant) - both
    /// keys must keep resolving to the same document, which is what <c>ReferenceEnrichmentService.RefreshBookReferenceAsync</c>'s
    /// multi-provider refresh fix (see docs/findings/providers.md) depends on.
    /// </summary>
    [Fact]
    public async Task FindByExternalIdAsync_FindsTheSameDocument_ByEitherOfTwoCoexistingProviderKeys()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var title = $"Multi Provider Book Title {Guid.NewGuid()}";
        var openLibraryId = TestExternalId.New();
        var bnfId = $"ark:/12148/{Guid.NewGuid():N}";

        var created = await CreateReferenceAsync(repository, new BookReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = openLibraryId, ["bnf"] = bnfId }
        });

        var foundByOpenLibrary = await repository.FindByExternalIdAsync("openlibrary", openLibraryId);
        var foundByBnf = await repository.FindByExternalIdAsync("bnf", bnfId);

        foundByOpenLibrary.Should().NotBeNull();
        foundByBnf.Should().NotBeNull();
        foundByOpenLibrary!.Id.Should().Be(created.Id);
        foundByBnf!.Id.Should().Be(created.Id);
    }

    /// <summary>
    /// A reference document carries its author as a <see cref="BookReferenceModel.AuthorReferenceId"/>, never as text, so the repository has nothing to build a complete alias from - and a creator-less one is exactly the half-key this collection must never hold, since it would answer for every author at once.
    /// </summary>
    [Fact]
    public async Task UpsertAsync_AddsNoCanonicalAlias_BecauseItCannotKnowTheAuthor()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var title = $"Canonical Only Book Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new BookReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2010,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = TestExternalId.New() }
        });

        var found = await repository.FindByIdAsync(created.Id!);

        found.Should().NotBeNull();
        found!.MatchedAliases.Should().BeEmpty();
    }

    /// <summary>
    /// An ISBN names one printing outright, which is what makes it worth its own lookup: a tenant who typed the French title of an English book matches on it and nothing else.
    /// </summary>
    [Fact]
    public async Task FindByIsbnAsync_MatchesTheAliasThatWasConfirmedUnderThatIsbn()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var title = $"Isbn Keyed Book {Guid.NewGuid()}";
        var isbn = $"978{Random.Shared.NextInt64(1000000000, 9999999999):D10}";

        var created = await CreateReferenceAsync(repository, new BookReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2011,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = title.ToLowerInvariant(), Year = 2011, Creator = "some author", Isbn = isbn }]
        });

        var found = await repository.FindByIsbnAsync(isbn);

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    [Fact]
    public async Task FindByIsbnAsync_MatchesNothing_WhenNoAliasWasConfirmedUnderThatIsbn()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();

        var found = await repository.FindByIsbnAsync($"978{Random.Shared.NextInt64(1000000000, 9999999999):D10}");

        found.Should().BeNull();
    }

    /// <summary>
    /// The same work is published again every few years, so a tenant's year routinely names an edition no alias was ever confirmed under - the title+author lookup is what still finds the work, and <c>FindSingleMatchAsync</c> is what keeps it from choosing between two genuinely different books.
    /// </summary>
    [Fact]
    public async Task FindByTitleAsync_MatchesAWorkWhoseOnlyAliasCarriesADifferentEditionYear()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IBookReferenceRepository>();
        var title = $"Reprinted Book Title {Guid.NewGuid()}";

        var created = await CreateReferenceAsync(repository, new BookReferenceModel
        {
            Title = title,
            TitleNormalized = title.ToLowerInvariant(),
            Year = 2011,
            ExternalIds = new Dictionary<string, string> { ["openlibrary"] = TestExternalId.New() },
            MatchedAliases = [new ReferenceMatchModel { Title = title.ToLowerInvariant(), Year = 2011, Creator = "some author" }]
        });

        var found = await repository.FindByTitleAsync(title, "Some Author");

        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
    }

    private async Task<BookReferenceModel> CreateReferenceAsync(IBookReferenceRepository repository, BookReferenceModel model)
    {
        var created = await repository.UpsertAsync(model);
        TrackDocument("book_reference", created.Id);
        return created;
    }
}
