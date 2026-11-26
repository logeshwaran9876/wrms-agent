namespace WRMS.Agent.Models;

/// <summary>
/// Evaluation and application result for an individual policy rule.
/// </summary>
public sealed class PolicyRuleResult
{
    public string RuleType { get; set; } = string.Empty;

    public string Target { get; set; } = string.Empty;

    public bool Success { get; set; }

    public string Status { get; set; } = string.Empty;

    public string Message { get; set; } = string.Empty;

    public static PolicyRuleResult Succeeded(string ruleType, string target, string message) =>
        new() { RuleType = ruleType, Target = target, Success = true, Status = Constants.PolicyConstants.Statuses.Success, Message = message };

    public static PolicyRuleResult Failed(string ruleType, string target, string message) =>
        new() { RuleType = ruleType, Target = target, Success = false, Status = Constants.PolicyConstants.Statuses.Failed, Message = message };

    public static PolicyRuleResult Skipped(string ruleType, string target, string message) =>
        new() { RuleType = ruleType, Target = target, Success = true, Status = Constants.PolicyConstants.Statuses.Skipped, Message = message };

    public static PolicyRuleResult Unsupported(string ruleType, string target, string message) =>
        new() { RuleType = ruleType, Target = target, Success = true, Status = Constants.PolicyConstants.Statuses.Unsupported, Message = message };
}

