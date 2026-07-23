using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One document per user, holding opt-in/opt-out toggles for features that are useful but not something
/// every user wants surfaced (see <see cref="Repositories.IUserPreferencesRepository"/>). A new feature of
/// this kind adds its own named boolean property here, the same convention every other flag in this
/// codebase already follows (e.g. <see cref="MovieModel.IsFavorite"/>) - not a generic settings dictionary.
/// </summary>
public class UserPreferencesModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    /// <summary>
    /// Shows an "open in a new tab" link to https://www.chasse-aux-livres.fr/{isbn} next to a book's ISBN
    /// field on <c>BookDetail.razor</c>, for users who use that site to price-check/verify French books.
    /// </summary>
    public bool ShowChasseAuxLivresLink { get; set; }
}
