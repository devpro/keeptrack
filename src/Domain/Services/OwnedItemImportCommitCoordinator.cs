using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Creates or merges reviewed import rows across the six owned-item types, written once.
/// Both multi-type importers (<c>AmazonImportController</c>, <c>GenericImportController</c>) hand it a list of <see cref="OwnedItemImportInput"/>
/// and get per-type <see cref="OwnedItemImportCommitCounts"/> back, so neither repeats the per-type branching.
/// The merge decision comes from <see cref="OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/>:
/// this only splits the inputs by <see cref="ImportMediaType"/>, supplies each type's construction delegates and persists the plan.
/// Repository access lives here rather than in a controller so the two controllers share it.
/// </summary>
public static class OwnedItemImportCommitCoordinator
{
    public static async Task<OwnedItemImportCommitCounts> CommitAsync(
        string ownerId,
        IReadOnlyList<OwnedItemImportInput> inputs,
        OwnedItemRepositorySet repositories)
    {
        var counts = new OwnedItemImportCommitCounts();

        await CommitTypeAsync(
            SelectRows(inputs, ImportMediaType.Book), counts.Books, counts, ownerId, repositories.Books,
            new BookModel { OwnerId = ownerId, Title = string.Empty, Author = string.Empty },
            Adapter(
                b => b.Title, b => b.OwnedVersions.Select(v => v.Reference),
                input => new BookModel
                {
                    OwnerId = ownerId,
                    Title = input.Title,
                    Author = input.Author ?? string.Empty,
                    Year = input.Year,
                    Isbn = input.Isbn,
                    Notes = input.ProvenanceNotes,
                    OwnedVersions = [input.OwnedVersion]
                },
                (book, input) => book.OwnedVersions.Add(input.OwnedVersion)));

        await CommitTypeAsync(
            SelectRows(inputs, ImportMediaType.Movie), counts.Movies, counts, ownerId, repositories.Movies,
            new MovieModel { OwnerId = ownerId, Title = string.Empty },
            Adapter(
                m => m.Title, m => m.OwnedVersions.Select(v => v.Reference),
                input => new MovieModel
                {
                    OwnerId = ownerId,
                    Title = input.Title,
                    Year = input.Year,
                    Notes = input.ProvenanceNotes,
                    OwnedVersions = [input.OwnedVersion]
                },
                (movie, input) => movie.OwnedVersions.Add(input.OwnedVersion)));

        await CommitTypeAsync(
            SelectRows(inputs, ImportMediaType.TvShow), counts.TvShows, counts, ownerId, repositories.TvShows,
            new TvShowModel { OwnerId = ownerId, Title = string.Empty },
            Adapter(
                t => t.Title, t => t.OwnedVersions.Select(v => v.Reference),
                input => new TvShowModel
                {
                    OwnerId = ownerId,
                    Title = input.Title,
                    Year = input.Year,
                    Notes = input.ProvenanceNotes,
                    OwnedVersions = [input.OwnedVersion]
                },
                (tvShow, input) => tvShow.OwnedVersions.Add(input.OwnedVersion)));

        await CommitTypeAsync(
            SelectRows(inputs, ImportMediaType.VideoGame), counts.VideoGames, counts, ownerId, repositories.VideoGames,
            new VideoGameModel { OwnerId = ownerId, Title = string.Empty },
            Adapter(
                g => g.Title, g => g.Platforms.Select(p => p.Reference),
                input => new VideoGameModel
                {
                    OwnerId = ownerId,
                    Title = input.Title,
                    Year = input.Year,
                    Notes = input.ProvenanceNotes,
                    Platforms = [ToPlatform(input)]
                },
                (game, input) => game.Platforms.Add(ToPlatform(input))));

        await CommitTypeAsync(
            SelectRows(inputs, ImportMediaType.Gear), counts.Gear, counts, ownerId, repositories.Gear,
            new GearModel { OwnerId = ownerId, Title = string.Empty },
            Adapter(
                g => g.Title, g => g.OwnedVersions.Select(v => v.Reference),
                input => new GearModel
                {
                    OwnerId = ownerId,
                    Title = input.Title,
                    Year = input.Year,
                    Notes = input.ProvenanceNotes,
                    OwnedVersions = [input.OwnedVersion]
                },
                (gear, input) => gear.OwnedVersions.Add(input.OwnedVersion)));

        await CommitTypeAsync(
            SelectRows(inputs, ImportMediaType.Collectible), counts.Collectibles, counts, ownerId, repositories.Collectibles,
            new CollectibleModel { OwnerId = ownerId, Title = string.Empty },
            Adapter(
                c => c.Title, c => c.OwnedVersions.Select(v => v.Reference),
                input => new CollectibleModel
                {
                    OwnerId = ownerId,
                    Title = input.Title,
                    Year = input.Year,
                    Notes = input.ProvenanceNotes,
                    OwnedVersions = [input.OwnedVersion]
                },
                (collectible, input) => collectible.OwnedVersions.Add(input.OwnedVersion)));

        return counts;
    }

    /// <summary>
    /// A video game's owned copy is a <see cref="VideoGamePlatformModel"/> with a required platform,
    /// not an <see cref="OwnedVersionModel"/>, so the purchase fields are copied onto a new platform entry.
    /// </summary>
    private static VideoGamePlatformModel ToPlatform(OwnedItemImportInput input) => new()
    {
        Platform = input.Platform!,
        CopyType = input.OwnedVersion.CopyType,
        ProductName = input.OwnedVersion.ProductName,
        Price = input.OwnedVersion.Price,
        Vendor = input.OwnedVersion.Vendor,
        AcquiredAt = input.OwnedVersion.AcquiredAt,
        Reference = input.OwnedVersion.Reference
    };

    private static List<OwnedItemImportInput> SelectRows(IReadOnlyList<OwnedItemImportInput> inputs, ImportMediaType mediaType) =>
        inputs.Where(i => i.MediaType == mediaType).ToList();

    private static OwnedItemImportAdapter<TModel, OwnedItemImportInput> Adapter<TModel>(
        System.Func<TModel, string> getExistingTitle,
        System.Func<TModel, IEnumerable<string?>> getExistingReferences,
        System.Func<OwnedItemImportInput, TModel> createNew,
        System.Action<TModel, OwnedItemImportInput> appendOwnedCopy)
        where TModel : class =>
        new(getExistingTitle, getExistingReferences, i => i.Title, i => i.OwnedVersion.Reference, createNew, appendOwnedCopy);

    private static async Task CommitTypeAsync<TModel>(
        List<OwnedItemImportInput> inputs,
        TypeCounts typeCounts,
        OwnedItemImportCommitCounts counts,
        string ownerId,
        IDataRepository<TModel> repository,
        TModel blankSample,
        OwnedItemImportAdapter<TModel, OwnedItemImportInput> adapter)
        where TModel : class, IHasIdAndOwnerId
    {
        if (inputs.Count == 0)
        {
            return;
        }

        var existing = (await repository.FindAllAsync(ownerId, 1, int.MaxValue, null, blankSample)).Items;

        var plan = OwnedItemImportMergeService.ComputeCommitPlan(existing, inputs, adapter);

        foreach (var item in plan.ItemsToCreate)
        {
            await repository.CreateAsync(item);
        }

        foreach (var item in plan.ItemsToUpdate)
        {
            await repository.UpdateAsync(item.Id!, item, ownerId);
        }

        typeCounts.Created = plan.ItemsToCreate.Count;
        typeCounts.MergedInto = plan.ItemsToUpdate.Count;
        typeCounts.Skipped = plan.OwnedCopiesSkipped;
        counts.RowsImported += plan.OwnedCopiesAdded;
        counts.SkippedTitles.AddRange(plan.SkippedTitles);
    }
}
