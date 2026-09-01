using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;

namespace Keeptrack.Domain.Services;

/// <summary>
/// The single place the "create/merge a set of reviewed import rows across the six owned-item types" algorithm
/// lives. Both owned-item importers (<c>AmazonImportController</c> and <c>GenericImportController</c>) hand it a
/// flat list of <see cref="OwnedItemImportInput"/> and get back per-type <see cref="OwnedItemImportCommitCounts"/> -
/// neither duplicates the per-type branching. The actual merge/dedup decision for each type still comes from the
/// generic <see cref="OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/>; this coordinator only
/// fans the inputs out by <see cref="ImportMediaType"/>, supplies each type's model-construction delegates, and
/// persists the resulting plan.
/// Repository access lives here (not in a controller) precisely so the two controllers share it; that's the same
/// tradeoff <see cref="OwnedItemImportMergeService"/> already made by taking the owner's already-fetched items.
/// </summary>
public static class OwnedItemImportCommitCoordinator
{
    public static async Task<OwnedItemImportCommitCounts> CommitAsync(
        string ownerId,
        IReadOnlyList<OwnedItemImportInput> inputs,
        IBookRepository bookRepository,
        IMovieRepository movieRepository,
        ITvShowRepository tvShowRepository,
        IVideoGameRepository videoGameRepository,
        IGearRepository gearRepository,
        ICollectibleRepository collectibleRepository)
    {
        var counts = new OwnedItemImportCommitCounts();

        await CommitTypeAsync(
            inputs, ImportMediaType.Book, counts.Books, counts, ownerId, bookRepository,
            new BookModel { OwnerId = ownerId, Title = string.Empty, Author = string.Empty },
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
            (book, input) => book.OwnedVersions.Add(input.OwnedVersion));

        await CommitTypeAsync(
            inputs, ImportMediaType.Movie, counts.Movies, counts, ownerId, movieRepository,
            new MovieModel { OwnerId = ownerId, Title = string.Empty },
            m => m.Title, m => m.OwnedVersions.Select(v => v.Reference),
            input => new MovieModel
            {
                OwnerId = ownerId,
                Title = input.Title,
                Year = input.Year,
                Notes = input.ProvenanceNotes,
                OwnedVersions = [input.OwnedVersion]
            },
            (movie, input) => movie.OwnedVersions.Add(input.OwnedVersion));

        await CommitTypeAsync(
            inputs, ImportMediaType.TvShow, counts.TvShows, counts, ownerId, tvShowRepository,
            new TvShowModel { OwnerId = ownerId, Title = string.Empty },
            t => t.Title, t => t.OwnedVersions.Select(v => v.Reference),
            input => new TvShowModel
            {
                OwnerId = ownerId,
                Title = input.Title,
                Year = input.Year,
                Notes = input.ProvenanceNotes,
                OwnedVersions = [input.OwnedVersion]
            },
            (tvShow, input) => tvShow.OwnedVersions.Add(input.OwnedVersion));

        await CommitTypeAsync(
            inputs, ImportMediaType.VideoGame, counts.VideoGames, counts, ownerId, videoGameRepository,
            new VideoGameModel { OwnerId = ownerId, Title = string.Empty },
            g => g.Title, g => g.Platforms.Select(p => p.Reference),
            input => new VideoGameModel
            {
                OwnerId = ownerId,
                Title = input.Title,
                Year = input.Year,
                Notes = input.ProvenanceNotes,
                Platforms = [ToPlatform(input)]
            },
            (game, input) => game.Platforms.Add(ToPlatform(input)));

        await CommitTypeAsync(
            inputs, ImportMediaType.Gear, counts.Gear, counts, ownerId, gearRepository,
            new GearModel { OwnerId = ownerId, Title = string.Empty },
            g => g.Title, g => g.OwnedVersions.Select(v => v.Reference),
            input => new GearModel
            {
                OwnerId = ownerId,
                Title = input.Title,
                Year = input.Year,
                Notes = input.ProvenanceNotes,
                OwnedVersions = [input.OwnedVersion]
            },
            (gear, input) => gear.OwnedVersions.Add(input.OwnedVersion));

        await CommitTypeAsync(
            inputs, ImportMediaType.Collectible, counts.Collectibles, counts, ownerId, collectibleRepository,
            new CollectibleModel { OwnerId = ownerId, Title = string.Empty },
            c => c.Title, c => c.OwnedVersions.Select(v => v.Reference),
            input => new CollectibleModel
            {
                OwnerId = ownerId,
                Title = input.Title,
                Year = input.Year,
                Notes = input.ProvenanceNotes,
                OwnedVersions = [input.OwnedVersion]
            },
            (collectible, input) => collectible.OwnedVersions.Add(input.OwnedVersion));

        return counts;
    }

    /// <summary>
    /// A video game's owned copy is a <see cref="VideoGamePlatformModel"/> (with a required platform), not an
    /// <see cref="OwnedVersionModel"/> - so its shared purchase fields are copied off the input's owned version
    /// onto a fresh platform entry. Built fresh per call since each input maps to exactly one create-or-append.
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

    private static async Task CommitTypeAsync<TModel>(
        IReadOnlyList<OwnedItemImportInput> allInputs,
        ImportMediaType mediaType,
        TypeCounts typeCounts,
        OwnedItemImportCommitCounts counts,
        string ownerId,
        IDataRepository<TModel> repository,
        TModel blankSample,
        System.Func<TModel, string> getExistingTitle,
        System.Func<TModel, IEnumerable<string?>> getExistingReferences,
        System.Func<OwnedItemImportInput, TModel> createNew,
        System.Action<TModel, OwnedItemImportInput> appendOwnedCopy)
        where TModel : class, IHasIdAndOwnerId
    {
        var inputs = allInputs.Where(i => i.MediaType == mediaType).ToList();
        if (inputs.Count == 0)
        {
            return;
        }

        var existing = (await repository.FindAllAsync(ownerId, 1, int.MaxValue, null, blankSample)).Items;

        var adapter = new OwnedItemImportAdapter<TModel, OwnedItemImportInput>(
            getExistingTitle, getExistingReferences,
            i => i.Title, i => i.OwnedVersion.Reference,
            createNew, appendOwnedCopy);

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
