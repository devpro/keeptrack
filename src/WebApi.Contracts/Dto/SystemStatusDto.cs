using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Operational snapshot for the admin "System" panel: how the instance answering this request is
/// configured, plus the cluster-wide (MongoDB-backed) view of the reference-sync lease and recent
/// background jobs.
/// </summary>
public class SystemStatusDto
{
    /// <summary>
    /// Name of the instance (the pod, under Kubernetes) that answered this request. With multiple
    /// replicas behind a load balancer, refreshing may legitimately show a different name each time.
    /// </summary>
    public required string InstanceName { get; set; }

    /// <summary>Whether the periodic reference-data sync loop is enabled on this instance.</summary>
    public bool IsReferenceSyncEnabled { get; set; }

    /// <summary>The effective book reference provider on this instance.</summary>
    public required string BookProvider { get; set; }

    /// <summary>
    /// The reference-sync single-runner lease, or null when no sync pass has ever been elected.
    /// Shared state (MongoDB), identical from every instance.
    /// </summary>
    public SystemLeaseDto? ReferenceSyncLease { get; set; }

    /// <summary>Most recent background jobs (imports, syncs), newest first. Shared state (MongoDB).</summary>
    public List<SystemJobDto> RecentJobs { get; set; } = [];
}

/// <summary>
/// A distributed lease's current state.
/// </summary>
public class SystemLeaseDto
{
    /// <summary>The instance (pod) holding or last holding the lease.</summary>
    public required string Holder { get; set; }

    /// <summary>When the lease expires or expired (UTC).</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>True while the lease is unexpired - the holder ran (or is running) a sync pass recently.</summary>
    public bool IsLive { get; set; }
}

/// <summary>
/// One background job's progress, as shown on the admin system panel.
/// </summary>
public class SystemJobDto
{
    /// <summary>Which feature the job belongs to ("Import", "ReferenceSync").</summary>
    public required string Kind { get; set; }

    /// <summary>The job's current (or terminal) stage name.</summary>
    public required string Stage { get; set; }

    /// <summary>The failure message, when the job failed.</summary>
    public string? ErrorMessage { get; set; }

    /// <summary>When the job was started (UTC).</summary>
    public DateTime CreatedAt { get; set; }
}
