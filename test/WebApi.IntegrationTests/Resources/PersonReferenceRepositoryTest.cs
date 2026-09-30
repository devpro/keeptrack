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
/// Exercises <see cref="IPersonReferenceRepository"/> directly against real MongoDB - the dictionary-key
/// filter behind <c>FindByExternalIdAsync</c> (a string field-path filter, not an expression indexer -
/// see the comment in <c>PersonReferenceRepository</c>) is exactly the kind of new, hand-written Mongo
/// query that has hidden real bugs in this codebase before.
/// </summary>
public class PersonReferenceRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    [Fact]
    public async Task UpsertAsync_ThenFindByExternalIdAsync_RoundTripsAndDeduplicatesByProviderAndId()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IPersonReferenceRepository>();
        var tmdbId = TestExternalId.New();

        var created = await repository.UpsertAsync(new PersonReferenceModel
        {
            Name = "Test Actor",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = tmdbId }
        });
        TrackDocument("person_reference", created.Id);

        var found = await repository.FindByExternalIdAsync("tmdb", tmdbId);
        found.Should().NotBeNull();
        found!.Id.Should().Be(created.Id);
        found.Name.Should().Be("Test Actor");

        // upserting again with the same id (simulating a second show crediting the same actor) must
        // update the existing document, not create a second one
        var updated = await repository.UpsertAsync(new PersonReferenceModel
        {
            Id = created.Id,
            Name = "Test Actor (updated)",
            ExternalIds = new Dictionary<string, string> { ["tmdb"] = tmdbId }
        });

        updated.Id.Should().Be(created.Id);
        (await repository.FindByExternalIdAsync("tmdb", tmdbId))!.Name.Should().Be("Test Actor (updated)");
    }

    [Fact]
    public async Task FindByExternalIdAsync_ReturnsNull_WhenNoPersonHasThatExternalId()
    {
        using var scope = Factory.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IPersonReferenceRepository>();

        var found = await repository.FindByExternalIdAsync("tmdb", TestExternalId.New());

        found.Should().BeNull();
    }
}
