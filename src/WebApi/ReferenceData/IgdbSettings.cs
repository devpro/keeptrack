namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The Twitch application credentials IGDB authenticates with (IGDB is part of Twitch, and its API has no key
/// of its own - you register an application at dev.twitch.tv and exchange the pair for an app access token,
/// see <see cref="IgdbTokenProvider"/>).
/// <para>
/// Both are nullable and a missing <c>Igdb</c> section is a supported state, the same shape as
/// <see cref="OmdbSettings"/>: a deployment with no credentials still boots, and <see cref="IgdbClient"/>
/// short-circuits to empty results rather than failing every request. That matters because IGDB is the
/// *default* video game provider - a hard requirement here would take the whole API down on a missing setting.
/// </para>
/// </summary>
public class IgdbSettings
{
    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }

    /// <summary>Whether both credentials are present - the one check every IGDB call path leads with.</summary>
    public bool IsConfigured => !string.IsNullOrWhiteSpace(ClientId) && !string.IsNullOrWhiteSpace(ClientSecret);
}
