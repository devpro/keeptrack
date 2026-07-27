using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// The six per-type delegates <see cref="Services.OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/>
/// needs to run its generic merge algorithm against a specific trackable type (<c>BookModel</c>/<c>MovieModel</c>/
/// <c>TvShowModel</c>/<c>VideoGameModel</c>/...) and its own request-item shape, bundled into one value instead of
/// threaded individually through every method in the call chain (was flagged by Sonar's S107 "too many parameters"
/// on three methods that all repeated the same six params).
/// </summary>
public sealed record OwnedItemImportAdapter<TModel, TRequestItem>(
    Func<TModel, string> GetExistingTitle,
    Func<TModel, IEnumerable<string?>> GetExistingReferences,
    Func<TRequestItem, string> GetItemTitle,
    Func<TRequestItem, string?> GetItemReference,
    Func<TRequestItem, TModel> CreateNew,
    Action<TModel, TRequestItem> AppendOwnedCopy)
    where TModel : class;
