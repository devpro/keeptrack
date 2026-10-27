using System.Collections.Generic;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// The <c>matched_aliases</c> array every reference collection carries: the local match key a title resolves through before any provider.
/// An interface, like <see cref="IHasReferenceRating"/>,
/// so the <c>ElemMatch</c> lookups are written once for all five entities (see <see cref="Repositories.ReferenceAliasQueries"/>).
/// </summary>
public interface IHasMatchedAliases
{
    List<ReferenceMatch> MatchedAliases { get; set; }
}
