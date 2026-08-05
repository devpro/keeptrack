using System;
using System.Collections.Generic;
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
/// Real-MongoDB coverage for the two queries the provider-reconciliation feature rests on, neither of which a
/// mocked repository can prove.
/// <para>
/// <c>FindWithoutExternalIdAsync</c> asks for the *absence* of a key inside an embedded document, which is the
/// same family of trap as the sync's staleness query and the <c>ReferenceId</c> null/empty one: a filter that
/// matches nothing looks exactly like a filter that found nothing wrong, and here it would report a clean
/// catalogue while every one of those references stayed invisible to the Explore exclusion.
/// <c>RepointReferenceAsync</c> is a cross-tenant <c>UpdateMany</c> whose whole purpose is that the items
/// actually move before the document they point at is deleted.
/// </para>
/// </summary>
public class ProviderReconciliationRepositoryTest(KestrelWebAppFactory<Program> factory) : DatabaseTestBase(factory)
{
    private const string Provider = "igdb";

    [Fact]
    public async Task FindWithoutExternalIdAsync_ReturnsExactlyTheReferencesMissingThatProvidersId()
    {
        var repository = ReferenceRepository();
        var marker = NewMarker();

        var adopted = await CreateReferenceAsync(repository, marker, "adopted", new Dictionary<string, string>
        {
            ["rawg"] = TestExternalId.New(),
            [Provider] = TestExternalId.New()
        });
        var stuck = await CreateReferenceAsync(repository, marker, "stuck", new Dictionary<string, string> { ["rawg"] = TestExternalId.New() });
        // no provider id at all - a document that has never resolved counts as a gap too
        var unlinked = await CreateReferenceAsync(repository, marker, "unlinked", []);

        var gaps = await MineAsync(repository, marker);

        gaps.Select(r => r.Id).Should().BeEquivalentTo([stuck.Id, unlinked.Id]);
        gaps.Select(r => r.Id).Should().NotContain(adopted.Id);
    }

    [Fact]
    public async Task RepointReferenceAsync_MovesEveryTenantsItemOntoTheSurvivingReference()
    {
        var itemRepository = ItemRepository();
        var ownerA = $"owner-a-{Guid.NewGuid():N}";
        var ownerB = $"owner-b-{Guid.NewGuid():N}";
        const string absorbedReferenceId = "6a5cba680e0bece35ad59728";
        const string keptReferenceId = "6a5cba680e0bece35ad59729";

        // two different tenants linked the same work through the document that is about to be absorbed - the
        // reference documents are shared, so repairing one has to repair it for both of them at once
        await CreateItemAsync(itemRepository, ownerA, "Elden Ring", absorbedReferenceId);
        await CreateItemAsync(itemRepository, ownerB, "Elden Ring", absorbedReferenceId);
        var untouched = await CreateItemAsync(itemRepository, ownerA, "Some Other Game", keptReferenceId);

        var moved = await itemRepository.RepointReferenceAsync(absorbedReferenceId, keptReferenceId);

        moved.Should().Be(2);
        var ownerAItems = await itemRepository.FindAllAsync(ownerA, 1, 50, null, new VideoGameModel { OwnerId = ownerA, Title = "" });
        ownerAItems.Items.Should().OnlyContain(item => item.ReferenceId == keptReferenceId);
        // an item linked to something else is left alone
        (await itemRepository.FindOneAsync(untouched.Id!, ownerA))!.ReferenceId.Should().Be(keptReferenceId);
    }

    /// <summary>
    /// The reference collection is shared and owner-less, so a parallel class's own gaps legitimately come
    /// back from this query too - filtering to this test's marker keeps the assertion exact without pretending
    /// the query is scoped.
    /// </summary>
    private static async Task<List<VideoGameReferenceModel>> MineAsync(IVideoGameReferenceRepository repository, string marker)
    {
        var gaps = await repository.FindWithoutExternalIdAsync(Provider);
        return gaps.Where(r => r.Title.StartsWith(marker, StringComparison.Ordinal)).ToList();
    }

    private async Task<VideoGameReferenceModel> CreateReferenceAsync(
        IVideoGameReferenceRepository repository, string marker, string suffix, Dictionary<string, string> externalIds)
    {
        var saved = await repository.UpsertAsync(new VideoGameReferenceModel
        {
            Title = $"{marker}-{suffix}",
            TitleNormalized = TitleNormalizer.Normalize($"{marker}-{suffix}"),
            ExternalIds = externalIds
        });
        TrackDocument("videogame_reference", saved.Id!);
        return saved;
    }

    private async Task<VideoGameModel> CreateItemAsync(IVideoGameRepository repository, string ownerId, string title, string referenceId)
    {
        var saved = await repository.CreateAsync(new VideoGameModel { OwnerId = ownerId, Title = title, ReferenceId = referenceId });
        TrackDocument("videogame", saved.Id!);
        return saved;
    }

    private IVideoGameReferenceRepository ReferenceRepository() => Resolve<IVideoGameReferenceRepository>();

    private IVideoGameRepository ItemRepository() => Resolve<IVideoGameRepository>();

    private TRepository Resolve<TRepository>()
        where TRepository : notnull
    {
        var scope = Factory.Services.CreateScope();
        TrackCleanup(() =>
        {
            scope.Dispose();
            return Task.CompletedTask;
        });
        return scope.ServiceProvider.GetRequiredService<TRepository>();
    }

    private static string NewMarker() => $"Reconciliation {Guid.NewGuid():N}";
}
