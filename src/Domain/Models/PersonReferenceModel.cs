using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// A person (actor, author, artist) from a provider, shared by every tenant.
/// Deduplicated across every work crediting them by provider id, never by name, since a credit carries an exact id.
/// </summary>
public class PersonReferenceModel : IHasExternalIds
{
    public string? Id { get; set; }

    public required string Name { get; set; }

    public string? ProfileImageUrl { get; set; }

    public required Dictionary<string, string> ExternalIds { get; set; }
}
