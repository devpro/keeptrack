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
    /// multi-provider refresh fix (see docs/code-quality-findings.md) depends on.
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

    [Fact]
    public async Task UpsertAsync_AlwaysIncludesTheCanonicalTitleAndYearInMatchedAliases_EvenIfTheCallerForgot()
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

        // this safety-net alias has no Creator (the model only carries AuthorReferenceId, not
        // denormalized text - see BookReferenceRepository.UpsertAsync), so it's unreachable via the
        // creator-required FindByTitleAsync/FindByTitleYearAsync; assert on the stored alias directly.
        var found = await repository.FindByIdAsync(created.Id!);

        found.Should().NotBeNull();
        found!.MatchedAliases.Should().ContainSingle(m => string.Equals(m.Title, title, StringComparison.OrdinalIgnoreCase) && m.Year == 2010);
    }

    private async Task<BookReferenceModel> CreateReferenceAsync(IBookReferenceRepository repository, BookReferenceModel model)
    {
        var created = await repository.UpsertAsync(model);
        TrackDocument("book_reference", created.Id);
        return created;
    }
}
