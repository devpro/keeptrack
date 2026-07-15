using System.Collections.Generic;
using AwesomeAssertions;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.Controllers;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Controllers;

[Trait("Category", "UnitTests")]
public class ReferenceImageHydratorTest
{
    [Fact]
    public void CollectReferenceIds_ReturnsDistinctNonEmptyIds()
    {
        var dtos = new List<MovieDto>
        {
            new() { Title = "Linked", ReferenceId = "ref-1" },
            new() { Title = "Same reference", ReferenceId = "ref-1" },
            new() { Title = "Other reference", ReferenceId = "ref-2" },
            new() { Title = "Unresolved null", ReferenceId = null },
            new() { Title = "Unresolved empty (pre-Mapperly data)", ReferenceId = "" }
        };

        var ids = ReferenceImageHydrator.CollectReferenceIds(dtos);

        ids.Should().BeEquivalentTo("ref-1", "ref-2");
    }

    [Fact]
    public void Apply_SetsImageUrlOnlyOnItemsWhoseReferenceWasFound()
    {
        var linked = new MovieDto { Title = "Linked", ReferenceId = "ref-1" };
        var missingReference = new MovieDto { Title = "Dangling link", ReferenceId = "ref-gone" };
        var unresolved = new MovieDto { Title = "Unresolved", ReferenceId = null };

        ReferenceImageHydrator.Apply(
            new List<MovieDto> { linked, missingReference, unresolved },
            new Dictionary<string, string?> { ["ref-1"] = "https://img.example/poster.jpg" });

        linked.ImageUrl.Should().Be("https://img.example/poster.jpg");
        missingReference.ImageUrl.Should().BeNull();
        unresolved.ImageUrl.Should().BeNull();
    }

    [Fact]
    public void Apply_PropagatesAReferenceWithNoImageAsNull()
    {
        var dto = new MovieDto { Title = "Linked, no poster", ReferenceId = "ref-1" };

        ReferenceImageHydrator.Apply(
            new List<MovieDto> { dto },
            new Dictionary<string, string?> { ["ref-1"] = null });

        dto.ImageUrl.Should().BeNull();
    }
}
