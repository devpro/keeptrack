using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The admin's provider-reconciliation view of a domain: how far its reference documents have caught up with
/// the provider that is currently the default, and which ones haven't.
/// <para>
/// A reference document is written under whichever provider linked it, so changing a domain's default leaves
/// the ones linked earlier in the previous provider's number space until they adopt an id in the new one.
/// That backlog is not cosmetic - the Explore feature recognises "the caller already has this" by the
/// discovery provider's id, so a reference stuck on the old provider is a game the owner tracks and keeps
/// being suggested anyway.
/// </para>
/// </summary>
public class ProviderReconciliationDto
{
    /// <summary>The domain's current default provider - the number space every reference is expected to carry an id in.</summary>
    public required string Provider { get; set; }

    /// <summary>That provider's display name, for the admin UI's prose.</summary>
    public required string ProviderDisplayName { get; set; }

    /// <summary>Reference documents in the domain, in total.</summary>
    public int TotalReferences { get; set; }

    /// <summary>The ones carrying no id in <see cref="Provider"/>'s number space, worst case first.</summary>
    public List<ProviderGapDto> Gaps { get; set; } = [];

    /// <summary>Sets of documents that look like the same work - see <see cref="DuplicateReferenceGroupDto"/>.</summary>
    public List<DuplicateReferenceGroupDto> Duplicates { get; set; } = [];
}

/// <summary>One reference document that has not adopted the current default provider's id.</summary>
public class ProviderGapDto
{
    public required string ReferenceId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    /// <summary>Provider keys this document does carry an id in ("rawg"), so the admin can see what it was linked through.</summary>
    public List<string> Providers { get; set; } = [];

    /// <summary>
    /// When the background pass last searched the default provider for this title, if ever. A recent stamp
    /// with the gap still open means the provider has no unambiguous match for it - the case this queue
    /// exists to resolve by hand.
    /// </summary>
    public DateTime? LastAttemptedAt { get; set; }
}

/// <summary>
/// Two or more reference documents describing what looks like one work. Every tenant item points at whichever
/// of them existed when it was linked, so the work's provider ids, ratings and cover are split across the set
/// and only one of them is ever recognised by Explore.
/// </summary>
public class DuplicateReferenceGroupDto
{
    public required string Title { get; set; }

    public List<DuplicateReferenceDto> References { get; set; } = [];
}

/// <summary>One document within a duplicate set, with enough detail to choose which one should survive a merge.</summary>
public class DuplicateReferenceDto
{
    public required string ReferenceId { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    /// <summary>Provider key to that provider's own id for this work.</summary>
    public Dictionary<string, string> ExternalIds { get; set; } = [];

    /// <summary>Rating source keys this document holds a value for - the knowledge a merge would otherwise lose.</summary>
    public List<string> RatingSources { get; set; } = [];

    public string? ImageUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}

/// <summary>An admin's choice of which provider id a stuck reference should adopt.</summary>
public class AdoptProviderIdRequestDto
{
    /// <summary>The id, in the current default provider's number space, of the game this reference describes.</summary>
    public required string ExternalId { get; set; }
}

/// <summary>An admin's choice of which of two duplicate reference documents survives.</summary>
public class MergeReferencesRequestDto
{
    /// <summary>The document that survives and gains whatever the other one knew.</summary>
    public required string KeepReferenceId { get; set; }

    /// <summary>The document that is absorbed and then deleted; every item linked to it is re-pointed first.</summary>
    public required string MergeReferenceId { get; set; }
}

/// <summary>What a merge did, so the admin sees that the tenants' items actually moved.</summary>
public class MergeReferencesResultDto
{
    public required string KeptReferenceId { get; set; }

    public long ItemsRepointed { get; set; }
}
