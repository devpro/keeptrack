using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The admin's provider reconciliation view of a domain: how many reference documents carry the default provider's id, and which do not.
/// <para>
/// A reference is written under the provider that linked it, so after a default changes, older ones stay in the previous provider's number space until they adopt an id.
/// That backlog matters, since Explore recognises what the caller has by the discovery provider's id, so a stuck reference is a tracked game that keeps being suggested.
/// </para>
/// </summary>
public class ProviderReconciliationDto
{
    /// <summary>The domain's default provider, whose id every reference should carry.</summary>
    public required string Provider { get; set; }

    /// <summary>That provider's display name, for the admin UI's prose.</summary>
    public required string ProviderDisplayName { get; set; }

    /// <summary>Reference documents in the domain, in total.</summary>
    public int TotalReferences { get; set; }

    /// <summary>The references with no id from <see cref="Provider"/>, worst case first.</summary>
    public List<ProviderGapDto> Gaps { get; set; } = [];

    /// <summary>Sets of documents that look like the same work (see <see cref="DuplicateReferenceGroupDto"/>).</summary>
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
    /// When the background pass last searched the default provider for this title, if ever.
    /// A recent stamp with the gap still open means the provider has no unambiguous match, the case this queue resolves by hand.
    /// </summary>
    public DateTime? LastAttemptedAt { get; set; }
}

/// <summary>
/// Two or more reference documents describing what looks like one work.
/// Every tenant item points at whichever existed when it linked, so the work's ids, ratings and cover are split across the set, and Explore recognises only one.
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

    /// <summary>Rating source keys this document holds a value for, which a careless merge would lose.</summary>
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
