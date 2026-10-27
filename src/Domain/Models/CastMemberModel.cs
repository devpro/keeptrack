namespace Keeptrack.Domain.Models;

/// <summary>
/// Embedded in <see cref="TvShowReferenceModel"/> and <see cref="MovieReferenceModel"/>: the top-billed cast is bounded and always fetched with the work.
/// See <see cref="ReferenceEpisodeModel"/> for the same embedding reasoning.
/// </summary>
public class CastMemberModel
{
    public required string PersonReferenceId { get; set; }

    public required string CharacterName { get; set; }

    public int Order { get; set; }
}
