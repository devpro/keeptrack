namespace Keeptrack.Domain.Models;

/// <summary>
/// Embedded within <see cref="TvShowReferenceModel"/>/<see cref="MovieReferenceModel"/> - a bounded,
/// always-fetched-with-the-show top-billed cast list. See <see cref="ReferenceEpisodeModel"/> for the
/// same embedding reasoning.
/// </summary>
public class CastMemberModel
{
    public required string PersonReferenceId { get; set; }

    public required string CharacterName { get; set; }

    public int Order { get; set; }
}
