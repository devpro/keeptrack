using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// A shared reference document, identified across databases by its provider ids rather than its MongoDB <c>_id</c>.
/// Every <c>*_reference</c> model implements it, so the reference-data import (<c>ReferenceDataImportService</c>) runs one matching algorithm over all six collections.
/// An <c>_id</c> is local to the database that minted it, while a provider id ("TMDB 1396") is the same fact everywhere, and unique on <c>external_ids.*</c>.
/// </summary>
public interface IHasExternalIds : IHasId
{
    /// <summary>
    /// Settable, unlike <see cref="IHasId.Id"/>: an import matching a document by provider id re-points the incoming copy at the id the target database already uses.
    /// </summary>
    new string? Id { get; set; }

    /// <summary>Provider name ("tmdb", "igdb", "googlebooks") to that provider's id for this document.</summary>
    Dictionary<string, string> ExternalIds { get; set; }
}
