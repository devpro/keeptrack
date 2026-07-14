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
/// Exercises <see cref="ITvShowRepository.SetReferenceLinkAsync"/> and
/// <see cref="ITvShowRepository.FindDistinctUnresolvedTitleYearsAsync"/> directly against real MongoDB -
/// these are new, hand-written Mongo queries (case-insensitive regex match, a "don't overwrite an
/// existing link" guard, a $group aggregation), exactly the kind of per-type override logic that has
/// historically hidden real bugs in this codebase (see the CarHistory $text-vs-$eq finding in
/// docs/code-quality-findings.md). Goes through the repository resolved from the test host's DI
/// container rather than HTTP, since the cross-tenant propagation this proves has nothing to do with
/// the calling user's own identity/role.
/// </summary>
public class TvShowReferenceLinkingTest(KestrelWebAppFactory<Program> factory) : IClassFixture<KestrelWebAppFactory<Program>>
{
    [Fact]
    public async Task SetReferenceLinkAsync_UpdatesEveryMatchingTenantsShow_ButNotOthers()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowRepository>();
        var title = $"Reference Linking Test Show {Guid.NewGuid()}";
        var canonicalTitle = $"Canonical {title}";
        const int year = 2021;

        var tenantAShow = await repository.CreateAsync(new TvShowModel { OwnerId = "reference-link-tenant-a", Title = title, Year = year });
        // different casing, different tenant: the match is case-insensitive and crosses tenants by design
        var tenantBShow = await repository.CreateAsync(new TvShowModel { OwnerId = "reference-link-tenant-b", Title = title.ToUpperInvariant(), Year = year });
        var differentYearShow = await repository.CreateAsync(new TvShowModel { OwnerId = "reference-link-tenant-a", Title = title, Year = year + 1 });
        var alreadyLinkedShow = await repository.CreateAsync(new TvShowModel
        {
            OwnerId = "reference-link-tenant-c",
            Title = title,
            Year = year,
            ReferenceId = "pre-existing-link"
        });

        try
        {
            var modifiedCount = await repository.SetReferenceLinkAsync(title, year, "reference-123", canonicalTitle);

            modifiedCount.Should().Be(2);
            var tenantAResult = (await repository.FindOneAsync(tenantAShow.Id!, "reference-link-tenant-a"))!;
            tenantAResult.ReferenceId.Should().Be("reference-123");
            // the tenant's own title is replaced with the reference's canonical name, not just the id
            tenantAResult.Title.Should().Be(canonicalTitle);
            (await repository.FindOneAsync(tenantBShow.Id!, "reference-link-tenant-b"))!.ReferenceId.Should().Be("reference-123");
            // An unset ReferenceId can round-trip as either "" (documents written before the
            // AutoMapper -> Mapperly migration) or null (new writes) - BeNullOrEmpty is the correct
            // "still unresolved" check that covers both generations.
            (await repository.FindOneAsync(differentYearShow.Id!, "reference-link-tenant-a"))!.ReferenceId.Should().BeNullOrEmpty();
            // a show that already has a link is never clobbered by a later automatic/admin resolution
            var alreadyLinkedResult = (await repository.FindOneAsync(alreadyLinkedShow.Id!, "reference-link-tenant-c"))!;
            alreadyLinkedResult.ReferenceId.Should().Be("pre-existing-link");
            alreadyLinkedResult.Title.Should().Be(title);
        }
        finally
        {
            await repository.DeleteAsync(tenantAShow.Id!, "reference-link-tenant-a");
            await repository.DeleteAsync(tenantBShow.Id!, "reference-link-tenant-b");
            await repository.DeleteAsync(differentYearShow.Id!, "reference-link-tenant-a");
            await repository.DeleteAsync(alreadyLinkedShow.Id!, "reference-link-tenant-c");
        }
    }

    [Fact]
    public async Task FindDistinctUnresolvedTitleYearsAsync_ReturnsDistinctUnlinkedTitleYearPairs()
    {
        using var scope = factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<ITvShowRepository>();
        var title = $"Unresolved Test Show {Guid.NewGuid()}";

        var showA = await repository.CreateAsync(new TvShowModel { OwnerId = "unresolved-tenant-a", Title = title, Year = 2022 });
        var showB = await repository.CreateAsync(new TvShowModel { OwnerId = "unresolved-tenant-b", Title = title, Year = 2022 });
        var linkedShow = await repository.CreateAsync(new TvShowModel
        {
            OwnerId = "unresolved-tenant-c",
            Title = title,
            Year = 2022,
            ReferenceId = "already-linked"
        });

        try
        {
            var unresolved = await repository.FindDistinctUnresolvedTitleYearsAsync();

            // two unlinked shows sharing (title, year) collapse into one queue entry; the already-linked one doesn't appear
            unresolved.Should().ContainSingle(p => p.Title == title && p.Year == 2022);
        }
        finally
        {
            await repository.DeleteAsync(showA.Id!, "unresolved-tenant-a");
            await repository.DeleteAsync(showB.Id!, "unresolved-tenant-b");
            await repository.DeleteAsync(linkedShow.Id!, "unresolved-tenant-c");
        }
    }
}
