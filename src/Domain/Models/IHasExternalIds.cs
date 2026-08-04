using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// A shared, owner-less reference document identified across environments by its provider ids rather than
/// by its Mongo <c>_id</c>. Every <c>*_reference</c> model implements it, which is what lets the reference-data
/// zip import (see <c>ReferenceDataImportService</c>) run one matching algorithm over all six collections:
/// an <c>_id</c> is local to the database that minted it, while a provider id ("this is TMDB 1396") is the same
/// fact everywhere and is what the unique partial indexes on <c>external_ids.*</c> already guarantee.
/// </summary>
public interface IHasExternalIds : IHasId
{
    /// <summary>
    /// Settable, unlike <see cref="IHasId.Id"/>: an import that matched a document by provider id has to
    /// re-point the incoming copy at the id the *target* database already stores it under.
    /// </summary>
    new string? Id { get; set; }

    /// <summary>Provider name (e.g. "tmdb", "igdb", "googlebooks") to that provider's id for this document.</summary>
    Dictionary<string, string> ExternalIds { get; set; }
}
