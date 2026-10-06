using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Progress of one background job (TV Time import, reference sync), persisted because the replica answering a status poll is not necessarily the one running the job.
/// Stage and result are plain strings, an enum name and a JSON payload, since their typed contracts belong to the web layer, which Domain does not depend on.
/// </summary>
public class BackgroundJobModel
{
    public required Guid JobId { get; set; }

    public required string OwnerId { get; set; }

    /// <summary>Which feature this job belongs to ("Import", "ReferenceSync"), for admin diagnostics.</summary>
    public required string Kind { get; set; }

    public required string Stage { get; set; }

    /// <summary>Stamped by the repository at creation, and read back to order diagnostics.</summary>
    public DateTime CreatedAt { get; set; }

    public string? ResultJson { get; set; }

    public string? ErrorMessage { get; set; }
}
