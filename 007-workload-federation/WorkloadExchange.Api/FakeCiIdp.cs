using System.Text.Json;
using Nuvora.Nexus.Sentinel.Tokens;

namespace WorkloadExchange.Api;

/// <summary>
/// A FAKE GitHub-Actions-style OIDC issuer living inside the sample process: a local RSA key
/// whose JWKS document is served through the injected <c>IRemoteJwksCache</c>, so
/// no real network or real GitHub is involved. In production the trust configuration points at
/// the real issuer (<c>https://token.actions.githubusercontent.com</c>) and this class does not
/// exist — the CI platform mints the tokens.
/// </summary>
public sealed class FakeCiIdp
{
    public const string Issuer = "https://fake-ci-idp.sample";
    public const string JwksUri = Issuer + "/.well-known/jwks";

    /// <summary>The <c>aud</c> CI workloads request their token FOR (never Sentinel's own API audience).</summary>
    public const string TrustAudience = "sentinel-federation";

    private readonly SigningKey _key = SigningKey.CreateNew(DateTimeOffset.UtcNow);

    /// <summary>RFC 7517 JWKS document for <see cref="JwksUri"/> — public parameters only.</summary>
    public string JwksDocument => JsonSerializer.Serialize(new { keys = new[] { _key.ToPublicJwk() } });

    /// <summary>
    /// Mints a GitHub-Actions-shaped workload token: <c>sub</c> identifies the repo+ref,
    /// extra claims carry the pipeline context that trust claim rules constrain.
    /// </summary>
    public string IssueToken(
        string sub = "repo:nuvoralabs/nexus:ref:refs/heads/master",
        string repository = "nuvoralabs/nexus",
        string gitRef = "refs/heads/master",
        string aud = TrustAudience,
        string issuer = Issuer)
    {
        var now = DateTimeOffset.UtcNow;
        return JwtCodec.Encode(_key, "JWT", payload =>
        {
            payload.WriteString("iss", issuer);
            payload.WriteString("aud", aud);
            payload.WriteString("sub", sub);
            payload.WriteString("repository", repository);
            payload.WriteString("ref", gitRef);
            payload.WriteNumber("iat", now.ToUnixTimeSeconds());
            payload.WriteNumber("exp", (now + TimeSpan.FromMinutes(5)).ToUnixTimeSeconds());
        });
    }
}
