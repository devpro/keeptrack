namespace Keeptrack.WebApi.Contracts.Dto;

public class UserPreferencesFeaturesDto
{
    /// <summary>
    /// Shows a link to chasse-aux-livres.fr next to a book's ISBN.
    /// </summary>
    public bool ShowChasseAuxLivresLink { get; set; }

    /// <summary>
    /// Shows an "open on Amazon" link next to an owned copy's Reference when the Amazon import created it, its Reference carrying an ASIN.
    /// </summary>
    public bool ShowAmazonProductLink { get; set; }
}
