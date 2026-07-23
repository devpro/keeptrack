namespace Keeptrack.WebApi.Contracts.Dto;

public class UserPreferencesFeaturesDto
{
    /// <summary>
    /// Shows an "open in a new tab" link to chasse-aux-livres.fr next to a book's ISBN field.
    /// </summary>
    public bool ShowChasseAuxLivresLink { get; set; }

    /// <summary>
    /// Shows an "open on Amazon" link next to an owned copy's Reference field whenever it was created by
    /// the Amazon order-history import (i.e. its Reference text carries an ASIN).
    /// </summary>
    public bool ShowAmazonProductLink { get; set; }
}
