namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The Twitch application credentials IGDB authenticates with: IGDB has no key of its own,
/// so an application registered at dev.twitch.tv exchanges them for an app access token (see <see cref="IgdbTokenProvider"/>).
/// <para>
/// Both are nullable and a missing <c>Igdb</c> section is supported, like <see cref="OmdbSettings"/>,
/// so a deployment without credentials boots and <see cref="IgdbClient"/> returns empty results.
/// IGDB being the default game provider, a hard requirement would take the whole API down on a missing setting.
/// </para>
/// </summary>
public class IgdbSettings
{
    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    /// <summary>Whether both credentials are present, which every IGDB call checks first.</summary>
    public bool IsConfigured => !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);
}
