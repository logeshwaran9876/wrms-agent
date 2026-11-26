namespace WRMS.Agent.Security;

using WRMS.Agent.Models;

/// <summary>
/// Service responsible for validating policy models and normalizing domains before application.
/// </summary>
public interface IPolicyValidationService
{
    /// <summary>
    /// Validates an incoming policy. Returns true if valid, or false along with validation error messages.
    /// </summary>
    (bool IsValid, List<string> Errors) ValidatePolicy(Policy policy);

    /// <summary>
    /// Normalizes a user/policy supplied domain string (strips protocol, port, paths, lowercases).
    /// </summary>
    string NormalizeDomain(string rawDomain);

    /// <summary>
    /// Validates if a normalized domain is a syntactically valid hostname.
    /// </summary>
    bool IsValidDomain(string domain);
}

