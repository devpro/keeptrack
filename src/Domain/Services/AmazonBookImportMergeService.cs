using System;
using System.Collections.Generic;
using System.Linq;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;

namespace Keeptrack.Domain.Services;

/// <summary>
/// Computes what to create/update when committing a set of user-reviewed Amazon order rows as books. Pure:
/// takes the owner's already-fetched books and the selected rows, returns a plan - all repository access
/// stays in <c>AmazonImportController</c>. Matching is by normalized title (<see cref="TitleNormalizer"/>,
/// the same "same title" rule the TV Time import already established), merging within the same commit
/// batch too: two selected rows sharing a title become one book with two owned versions, even if neither
/// existed before this commit.
/// </summary>
public static class AmazonBookImportMergeService
{
    private const string OrderReferencePrefix = "Amazon order ";

    /// <summary>
    /// The one place that formats an owned version's <see cref="OwnedVersionModel.Reference"/> for an
    /// imported order - human-readable, and also the dedup key <see cref="FindImportedOrderIds"/> looks for
    /// on a later re-import.
    /// </summary>
    public static string FormatOrderReference(string orderId) => OrderReferencePrefix + orderId;

    /// <summary>
    /// Order ids already referenced by an existing owned version - used at preview time to flag rows that
    /// look like they were imported before, so re-uploading a newer export doesn't duplicate them.
    /// </summary>
    public static HashSet<string> FindImportedOrderIds(IEnumerable<BookModel> existingBooks) =>
        existingBooks
            .SelectMany(book => book.OwnedVersions)
            .Select(version => version.Reference)
            .Where(reference => reference is not null && reference.StartsWith(OrderReferencePrefix, StringComparison.Ordinal))
            .Select(reference => reference![OrderReferencePrefix.Length..])
            .ToHashSet();

    public static AmazonBookImportPlan ComputeCommitPlan(string ownerId, IReadOnlyCollection<BookModel> existingBooks, IReadOnlyList<AmazonBookImportRequestItem> items)
    {
        var plan = new AmazonBookImportPlan();

        var byNormalizedTitle = new Dictionary<string, BookModel>();
        foreach (var book in existingBooks)
        {
            byNormalizedTitle.TryAdd(TitleNormalizer.Normalize(book.Title), book);
        }

        // Books created earlier in this same batch are tracked separately from pre-existing ones: a later
        // row matching one must only get its owned version appended (already reflected via BooksToCreate),
        // never also queued onto BooksToUpdate - it has no Id yet, so "updating" it would be meaningless.
        var createdThisBatch = new HashSet<BookModel>();

        foreach (var item in items)
        {
            var key = TitleNormalizer.Normalize(item.Title);

            if (byNormalizedTitle.TryGetValue(key, out var existing))
            {
                existing.OwnedVersions.Add(item.OwnedVersion);
                if (!createdThisBatch.Contains(existing) && !plan.BooksToUpdate.Contains(existing))
                {
                    plan.BooksToUpdate.Add(existing);
                }
            }
            else
            {
                var book = new BookModel
                {
                    OwnerId = ownerId,
                    Title = item.Title,
                    Author = string.Empty,
                    Year = item.Year,
                    Isbn = item.Isbn,
                    OwnedVersions = [item.OwnedVersion]
                };
                plan.BooksToCreate.Add(book);
                createdThisBatch.Add(book);

                // so a later row in the same batch sharing this title merges into it too, instead of
                // creating a second book
                byNormalizedTitle[key] = book;
            }

            plan.OwnedVersionsAdded++;
        }

        return plan;
    }
}
