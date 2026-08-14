using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.AspNetCore.HealthChecks;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Impersonation;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Ports;

namespace Governance.Api;

/// <summary>
/// Admin governance in one host: impersonation (act claim, target consent, the
/// /profile/me banner) and break-glass (flagged account, capped grants, alarms on login, drill
/// health check). Shared verbatim by Program.cs and the tests.
/// </summary>
public static class GovernanceComposition
{
    public const string Issuer = "https://governance.sample";
    public const string Audience = "governance-api";
    public const string DemoPassword = "governance-demo-password";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000015");

    // Fixed ids so the README's curl walkthrough and the tests agree on who is who.
    public static readonly Guid AdminId = Guid.Parse("00000015-0000-0000-0000-00000000000a");
    public static readonly Guid TargetId = Guid.Parse("00000015-0000-0000-0000-00000000000b");
    public static readonly Guid BreakGlassId = Guid.Parse("00000015-0000-0000-0000-00000000000c");

    public const string AdminEmail = "admin@clinic.sample";
    public const string TargetEmail = "taylor@clinic.sample";
    public const string BreakGlassEmail = "root@clinic.sample";

    public static IServiceCollection AddGovernanceApi(
        this IServiceCollection services, bool requireTargetConsent = false)
    {
        services.AddRouting();

        // Identity stores + grants source first: every Sentinel registration is TryAdd, so
        // whatever the host registers wins. Swap for AddSentinelEfCoreStores in production.
        var store = new InMemoryIdentityStore();
        var hasher = new PasswordHasher(
            new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1)); // cheap: teaching code
        Seed(store, hasher);

        services.AddSingleton(store);
        services.AddSingleton<IUserStore>(store);
        services.AddSingleton<IMfaStore>(store);
        services.AddSingleton<ISessionStore>(store);
        services.AddSingleton<ISubjectDataSource, GovernanceSubjectSource>();
        services.AddSingleton(hasher);

        // Alert mails (impersonation consent, break-glass logins) land here instead of an SMTP
        // relay — the tests read them, `dotnet run` logs them.
        services.AddSingleton<RecordingMailer>();
        services.AddSingleton<ISentinelMailer>(sp => sp.GetRequiredService<RecordingMailer>());

        services.Configure<SentinelTokenOptions>(o => o.Issuer = Issuer);
        services.AddSentinel(o =>
        {
            o.DefaultRealmId = RealmId;
            o.AllowDevelopmentDefaults = true; // sample-only ephemeral signing keys
        });
        services.AddSentinelAuthentication(o =>
        {
            o.Issuer = Issuer;
            o.Audience = Audience;
            o.DefaultRealmId = RealmId;
        });

        // The governance surface. Impersonation is opt-in; consent mode is a policy flag.
        services.AddSentinelImpersonation(o => o.RequireTargetConsent = requireTargetConsent);

        // Break-glass AFTER the subject source and AddSentinel: it DECORATES the registered
        // ISubjectDataSource (grant capping) and ILoginGate (alarm on login).
        services.AddSentinelBreakGlass(policy =>
        {
            policy.CappedPatterns = ["sentinel:global:*", "records:global:read"];
            policy.OperatorEmails = ["ops@clinic.sample"];
            policy.DrillIntervalDays = 90;
        });

        services.AddHealthChecks().AddSentinelBreakGlassHealthCheck();

        return services;
    }

    /// <summary>
    /// Three actors: a support admin who may impersonate, an ordinary target, and the
    /// break-glass account — an ordinary user with the <c>sentinel:break_glass</c> attribute and
    /// deliberately broad grants (the cap, not the role model, is what contains it).
    /// </summary>
    private static void Seed(InMemoryIdentityStore store, PasswordHasher hasher)
    {
        AddUser(store, hasher, AdminId, AdminEmail, "Alex Admin");
        AddUser(store, hasher, TargetId, TargetEmail, "Taylor Target");

        var breakGlass = AddUser(store, hasher, BreakGlassId, BreakGlassEmail, "Break Glass");
        breakGlass.Attributes[BreakGlassPolicy.BreakGlassAttribute] = true;
    }

    private static User AddUser(
        InMemoryIdentityStore store, PasswordHasher hasher, Guid id, string email, string displayName)
    {
        var user = new User
        {
            Id = id,
            RealmId = RealmId,
            Email = email,
            EmailVerified = true,
            DisplayName = displayName,
        };
        store.AddUser(user, new UserCredential
        {
            UserId = user.Id,
            Algorithm = hasher.Current.Name,
            Hash = hasher.Hash(DemoPassword),
        });
        return user;
    }

    public static IEndpointRouteBuilder MapGovernanceApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth();            // POST /auth/login
        endpoints.MapSentinelProfile();         // GET /profile/me (banner), /profile/permissions
        endpoints.MapSentinelImpersonation();   // POST /sentinel-admin/impersonation/start | /end | /active | /consent/approve
        endpoints.MapSentinelBreakGlass();      // GET /sentinel-admin/break-glass/status, POST …/drill-login-marker
        endpoints.MapHealthChecks("/health");   // Degraded while the drill is stale
        return endpoints;
    }
}
