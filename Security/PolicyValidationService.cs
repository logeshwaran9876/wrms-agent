namespace WRMS.Agent.Security;

using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using WRMS.Agent.Models;

/// <summary>
/// Validates policies against schema, versioning, and security constraints.
/// Normalizes and cleans domain names.
/// </summary>
public sealed class PolicyValidationService : IPolicyValidationService
{
    private readonly ILogger<PolicyValidationService> _logger;

    // RFC 1123 compliant domain name validation regex
    private static readonly Regex DomainRegex = new(
        @"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public PolicyValidationService(ILogger<PolicyValidationService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public (bool IsValid, List<string> Errors) ValidatePolicy(Policy policy)
    {
        var errors = new List<string>();

        if (policy == null)
        {
            errors.Add("Policy cannot be null.");
            return (false, errors);
        }

        if (string.IsNullOrWhiteSpace(policy.PolicyId))
        {
            errors.Add("PolicyId is required and cannot be empty.");
        }

        if (policy.PolicyVersion < 1)
        {
            errors.Add($"PolicyVersion must be greater than or equal to 1. Provided: {policy.PolicyVersion}");
        }

        if (policy.WebsiteRules != null)
        {
            for (var i = 0; i < policy.WebsiteRules.Count; i++)
            {
                var rule = policy.WebsiteRules[i];
                if (rule == null)
                {
                    errors.Add($"WebsiteRule at index {i} is null.");
                    continue;
                }

                if (string.IsNullOrWhiteSpace(rule.Domain))
                {
                    errors.Add($"WebsiteRule at index {i} has an empty domain.");
                    continue;
                }

                var normalized = NormalizeDomain(rule.Domain);
                if (!IsValidDomain(normalized))
                {
                    errors.Add($"WebsiteRule at index {i} has an invalid domain format: '{rule.Domain}' (normalized: '{normalized}').");
                }
            }
        }

        var isValid = errors.Count == 0;
        if (!isValid)
        {
            _logger.LogWarning("Policy validation failed with {Count} errors: {Errors}", errors.Count, string.Join("; ", errors));
        }

        return (isValid, errors);
    }

    public string NormalizeDomain(string rawDomain)
    {
        if (string.IsNullOrWhiteSpace(rawDomain))
        {
            return string.Empty;
        }

        var domain = rawDomain.Trim();

        // Strip URI protocol schemes if present
        if (domain.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            domain = domain["http://".Length..];
        }
        else if (domain.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            domain = domain["https://".Length..];
        }
        else if (domain.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase))
        {
            domain = domain["ftp://".Length..];
        }

        // Strip path, query, fragment
        var slashIndex = domain.IndexOf('/');
        if (slashIndex >= 0)
        {
            domain = domain[..slashIndex];
        }

        var questionIndex = domain.IndexOf('?');
        if (questionIndex >= 0)
        {
            domain = domain[..questionIndex];
        }

        var hashIndex = domain.IndexOf('#');
        if (hashIndex >= 0)
        {
            domain = domain[..hashIndex];
        }

        // Strip port if present
        var colonIndex = domain.IndexOf(':');
        if (colonIndex >= 0)
        {
            domain = domain[..colonIndex];
        }

        // Strip trailing dot if present
        domain = domain.TrimEnd('.');

        return domain.ToLowerInvariant().Trim();
    }

    public bool IsValidDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain) || domain.Length > 253)
        {
            return false;
        }

        // Check against RFC 1123 domain regex
        if (!DomainRegex.IsMatch(domain))
        {
            return false;
        }

        // Must contain at least one dot (TLD separator) e.g., "youtube.com"
        if (!domain.Contains('.'))
        {
            return false;
        }

        return true;
    }
}

