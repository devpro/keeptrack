using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// The six per-type delegates <see cref="Services.OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/> needs to run its generic merge over one trackable type
/// and its request-item shape.
/// Bundled into one value rather than passed separately through every method of the call chain (Sonar S107).
/// </summary>
public sealed record OwnedItemImportAdapter<TModel, TRequestItem>(
    Func<TModel, string> GetExistingTitle,
    Func<TModel, IEnumerable<string?>> GetExistingReferences,
    Func<TRequestItem, string> GetItemTitle,
    Func<TRequestItem, string?> GetItemReference,
    Func<TRequestItem, TModel> CreateNew,
    Action<TModel, TRequestItem> AppendOwnedCopy)
    where TModel : class;
