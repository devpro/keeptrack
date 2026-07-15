using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.Controllers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Controllers;

[Trait("Category", "UnitTests")]
public class ReferenceImageHydratorTest
{
    private static Task<List<MovieReferenceModel>> Repository(IReadOnlyCollection<string> requestedIds, List<MovieReferenceModel> references, List<IReadOnlyCollection<string>>? calls = null)
    {
        calls?.Add(requestedIds);
        return Task.FromResult(references);
    }

    [Fact]
    public async Task HydrateAsync_QueriesDistinctNonEmptyIdsOnce_AndSetsImageUrlOnMatchingItems()
    {
        var linked = new MovieDto { Title = "Linked", ReferenceId = "ref-1" };
        var sameReference = new MovieDto { Title = "Same reference", ReferenceId = "ref-1" };
        var missingReference = new MovieDto { Title = "Dangling link", ReferenceId = "ref-gone" };
        var unresolvedNull = new MovieDto { Title = "Unresolved null", ReferenceId = null };
        var unresolvedEmpty = new MovieDto { Title = "Unresolved empty (pre-Mapperly data)", ReferenceId = "" };
        var calls = new List<IReadOnlyCollection<string>>();

        await ReferenceImageHydrator.HydrateAsync(
            new List<MovieDto> { linked, sameReference, missingReference, unresolvedNull, unresolvedEmpty },
            ids => Repository(ids, [new MovieReferenceModel { Id = "ref-1", Title = "Linked", TitleNormalized = "linked", ExternalIds = new(), ImageUrl = "https://img.example/poster.jpg" }], calls),
            x => x.ImageUrl);

        calls.Should().ContainSingle().Which.Should().BeEquivalentTo("ref-1", "ref-gone");
        linked.ImageUrl.Should().Be("https://img.example/poster.jpg");
        sameReference.ImageUrl.Should().Be("https://img.example/poster.jpg");
        missingReference.ImageUrl.Should().BeNull();
        unresolvedNull.ImageUrl.Should().BeNull();
        unresolvedEmpty.ImageUrl.Should().BeNull();
    }

    [Fact]
    public async Task HydrateAsync_SkipsTheRepositoryEntirely_WhenNoItemIsLinked()
    {
        var calls = new List<IReadOnlyCollection<string>>();

        await ReferenceImageHydrator.HydrateAsync(
            new List<MovieDto> { new() { Title = "Unresolved", ReferenceId = null } },
            ids => Repository(ids, [], calls),
            x => x.ImageUrl);

        calls.Should().BeEmpty();
    }

    [Fact]
    public async Task HydrateAsync_PropagatesAReferenceWithNoImageAsNull()
    {
        var dto = new MovieDto { Title = "Linked, no poster", ReferenceId = "ref-1" };

        await ReferenceImageHydrator.HydrateAsync(
            new List<MovieDto> { dto },
            ids => Repository(ids, [new MovieReferenceModel { Id = "ref-1", Title = "Linked, no poster", TitleNormalized = "linked no poster", ExternalIds = new(), ImageUrl = null }]),
            x => x.ImageUrl);

        dto.ImageUrl.Should().BeNull();
    }
}
