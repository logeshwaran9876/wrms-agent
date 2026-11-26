namespace WRMS.Agent.Models;

/// <summary>
/// Aggregate result of applying an entire policy package to the Windows system.
/// </summary>
public sealed class PolicyApplyResult
{
    public bool Success { get; set; }

    public string Status { get; set; } = string.Empty;

    public string PolicyId { get; set; } = string.Empty;

    public int PolicyVersion { get; set; }

    public List<PolicyRuleResult> Rules { get; set; } = [];

    public List<string> Errors { get; set; } = [];

    public DateTimeOffset AppliedAt { get; set; } = DateTimeOffset.UtcNow;

    public static PolicyApplyResult Successful(string policyId, int version, List<PolicyRuleResult> rules) =>
        new()
        {
            Success = true,
            Status = Constants.PolicyConstants.Statuses.Success,
            PolicyId = policyId,
            PolicyVersion = version,
            Rules = rules,
            AppliedAt = DateTimeOffset.UtcNow
        };

    public static PolicyApplyResult Partial(string policyId, int version, List<PolicyRuleResult> rules, List<string> errors) =>
        new()
        {
            Success = false,
            Status = Constants.PolicyConstants.Statuses.PartialSuccess,
            PolicyId = policyId,
            PolicyVersion = version,
            Rules = rules,
            Errors = errors,
            AppliedAt = DateTimeOffset.UtcNow
        };

    public static PolicyApplyResult Failure(string policyId, int version, string error, List<PolicyRuleResult>? rules = null) =>
        new()
        {
            Success = false,
            Status = Constants.PolicyConstants.Statuses.Failed,
            PolicyId = policyId,
            PolicyVersion = version,
            Rules = rules ?? [],
            Errors = [error],
            AppliedAt = DateTimeOffset.UtcNow
        };

    public static PolicyApplyResult NoChange(string policyId, int version) =>
        new()
        {
            Success = true,
            Status = Constants.PolicyConstants.Statuses.NoChangeRequired,
            PolicyId = policyId,
            PolicyVersion = version,
            Rules = [],
            AppliedAt = DateTimeOffset.UtcNow
        };
}

