using System.Collections.Generic;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// The <c>matched_aliases</c> array every reference collection carries identically - the local match key a title resolves through before any provider is called.
/// Declared as an interface for the same reason as <see cref="IHasReferenceRating"/>: the <c>ElemMatch</c> lookups over it are one algorithm, not five (see <see cref="Repositories.ReferenceAliasQueries"/>), and the field is named the same on all five entities so nothing has to be passed as a lambda.
/// </summary>
public interface IHasMatchedAliases
{
    List<ReferenceMatch> MatchedAliases { get; set; }
}
