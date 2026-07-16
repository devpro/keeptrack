using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Progress of one background job (TV Time import, reference-data "sync now"), persisted so that in a
/// multi-replica deployment the replica answering a status poll doesn't have to be the replica running
/// the job. Stage and result are carried as plain strings (an enum name and a JSON payload respectively):
/// the typed stage/result contracts are a web-layer concern, and Domain must not depend on them.
/// </summary>
public class BackgroundJobModel
{
    public required Guid JobId { get; set; }

    public required string OwnerId { get; set; }

    /// <summary>Which feature this job belongs to ("Import", "ReferenceSync") - for admin diagnostics.</summary>
    public required string Kind { get; set; }

    public required string Stage { get; set; }

    /// <summary>Stamped by the repository at creation; carried back on reads for diagnostics ordering.</summary>
    public DateTime CreatedAt { get; set; }

    public string? ResultJson { get; set; }

    public string? ErrorMessage { get; set; }
}
