namespace Keeptrack.Domain.Models;

/// <summary>
/// The actual opt-in/opt-out toggles held by <see cref="UserPreferencesModel.Features"/>. A new feature of
/// this kind adds its own named boolean property here, the same convention every other flag in this
/// codebase already follows (e.g. <see cref="MovieModel.IsFavorite"/>) - not a generic settings dictionary.
/// </summary>
public class UserPreferencesFeaturesModel
{
    /// <summary>
    /// Shows an "open in a new tab" link to https://www.chasse-aux-livres.fr/{isbn} next to a book's ISBN
    /// field on <c>BookDetail.razor</c>, for users who use that site to price-check/verify French books.
    /// </summary>
    public bool ShowChasseAuxLivresLink { get; set; }

    /// <summary>
    /// Shows an "open on Amazon" link next to an owned copy's Reference field
    /// (<c>OwnedVersionFields.razor</c>, shared by every owned-copy type) whenever
    /// <see cref="Common.System.AmazonReference.TryExtractAsin"/> finds an ASIN in it - i.e. the copy was
    /// created by the Amazon order-history import.
    /// </summary>
    public bool ShowAmazonProductLink { get; set; }
}
