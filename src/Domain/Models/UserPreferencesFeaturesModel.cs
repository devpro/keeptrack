namespace Keeptrack.Domain.Models;

/// <summary>
/// The opt-in toggles held by <see cref="UserPreferencesModel.Features"/>.
/// A new toggle is a named boolean here, like every other flag (<see cref="MovieModel.IsFavorite"/>), never a generic settings dictionary.
/// </summary>
public class UserPreferencesFeaturesModel
{
    /// <summary>
    /// Shows a link to https://www.chasse-aux-livres.fr/{isbn} next to a book's ISBN on <c>BookDetail.razor</c>, a site for checking French books and their prices.
    /// </summary>
    public bool ShowChasseAuxLivresLink { get; set; }

    /// <summary>
    /// Shows an "open on Amazon" link next to an owned copy's Reference (<c>OwnedVersionFields.razor</c>) when <see cref="Common.System.AmazonReference.TryExtractAsin"/> finds an ASIN in it, meaning the Amazon import created the copy.
    /// </summary>
    public bool ShowAmazonProductLink { get; set; }
}
