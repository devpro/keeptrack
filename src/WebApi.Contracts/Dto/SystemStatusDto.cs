using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Operational snapshot for the admin "System" panel: how the answering instance is configured, plus the shared view of the reference sync lease and recent background jobs.
/// </summary>
public class SystemStatusDto
{
    /// <summary>
    /// Name of the instance (the Kubernetes pod) that answered this request.
    /// With several replicas behind a load balancer, each refresh can show another name.
    /// </summary>
    public required string InstanceName { get; set; }

    /// <summary>Whether the periodic reference-data sync loop is enabled on this instance.</summary>
    public bool IsReferenceSyncEnabled { get; set; }

    /// <summary>The effective book reference provider on this instance.</summary>
    public required string BookProvider { get; set; }

    /// <summary>The effective video game reference provider on this instance.</summary>
    public required string VideoGameProvider { get; set; }

    /// <summary>
    /// The reference sync lease, or null when no pass was ever elected, the same from every instance.
    /// </summary>
    public SystemLeaseDto? ReferenceSyncLease { get; set; }

    /// <summary>The most recent background jobs (imports, syncs), newest first.</summary>
    public List<SystemJobDto> RecentJobs { get; set; } = [];
}

/// <summary>
/// A distributed lease's current state.
/// </summary>
public class SystemLeaseDto
{
    /// <summary>The instance holding the lease, or the last one that did.</summary>
    public required string Holder { get; set; }

    /// <summary>When the lease expires or expired (UTC).</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>True while the lease is unexpired, the holder running or having just run a sync pass.</summary>
    public bool IsLive { get; set; }
}

/// <summary>
/// One background job's progress, as shown on the admin system panel.
/// </summary>
public class SystemJobDto
{
    /// <summary>Which feature the job belongs to ("Import", "ReferenceSync").</summary>
    public required string Kind { get; set; }

    /// <summary>The job's current or final stage name.</summary>
    public required string Stage { get; set; }

    /// <summary>The failure message, when the job failed.</summary>
    public string? ErrorMessage { get; set; }

    /// <summary>When the job was started (UTC).</summary>
    public DateTime CreatedAt { get; set; }
}
