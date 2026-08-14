using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore;
using Nuvora.Nexus.Sentinel.AspNetCore.DependencyInjection;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;
using Nuvora.Nexus.Sentinel.Audit;
using Nuvora.Nexus.Sentinel.Authentication;
using Nuvora.Nexus.Sentinel.Authorization;
using Nuvora.Nexus.Sentinel.DependencyInjection;
using Nuvora.Nexus.Sentinel.Identity;
using Nuvora.Nexus.Sentinel.Login;
using Nuvora.Nexus.Sentinel.Privacy;

namespace PersonalData.Api;

/// <summary>
/// The GDPR surface end to end: export (Art. 20 bundle), erasure (crypto-shred →
/// anonymize → redact) with the audit chain still verifying afterwards, and the shredder as an
/// app-facing primitive (the /notes endpoints store PII encrypted under the subject's key).
/// Shared verbatim by Program.cs and the tests.
/// </summary>
public static class PersonalDataComposition
{
    public const string Issuer = "https://personaldata.sample";
    public const string Audience = "personaldata-api";
    public const string DemoPassword = "personal-data-demo-password";

    public static readonly Guid RealmId = Guid.Parse("00000000-0000-0000-0000-000000000016");

    // Fixed ids so the README's curl walkthrough and the tests agree on who is who.
    public static readonly Guid AdminId = Guid.Parse("00000016-0000-0000-0000-00000000000a");
    public static readonly Guid JaneId = Guid.Parse("00000016-0000-0000-0000-00000000000b");

    public const string AdminEmail = "dpo@clinic.sample";
    public const string JaneEmail = "jane@clinic.sample";

    public static IServiceCollection AddPersonalDataApi(this IServiceCollection services)
    {
        services.AddRouting();

        var store = new InMemoryIdentityStore();
        var hasher = new PasswordHasher(
            new Argon2idPasswordHashAlgorithm(memoryKib: 8, iterations: 1, parallelism: 1)); // cheap: teaching code
        Seed(store, hasher);

        services.AddSingleton(store);
        services.AddSingleton<IUserStore>(store);
        services.AddSingleton<IMfaStore>(store);
        services.AddSingleton<ISessionStore>(store);
        services.AddSingleton<ISubjectDataSource, PersonalDataSubjectSource>();
        services.AddSingleton(hasher);

        // AddSentinelPrivacy does NOT default this port: erasure has to delete authenticators
        // and federated links wherever the host keeps them, so the host says where that is.
        // AddSentinelEfCoreStores registers the EF adapter; this sample keeps it in memory.
        services.AddSingleton<InMemoryPersonalDataSource>();
        services.AddSingleton<IPersonalDataSource>(sp => sp.GetRequiredService<InMemoryPersonalDataSource>());

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

        // Crypto-shredding + export/erasure + retention. The defaults keep security events for
        // a year and the admin audit chain forever (payloads redactable, hashes never).
        services.AddSentinelPrivacy();

        // App-level PII encrypted under the subject's key: destroying the key at erasure makes
        // every note unrecoverable without touching the notes table.
        services.AddSingleton<NotesVault>();

        return services;
    }

    private static void Seed(InMemoryIdentityStore store, PasswordHasher hasher)
    {
        AddUser(store, hasher, AdminId, AdminEmail, "Dana DPO");
        AddUser(store, hasher, JaneId, JaneEmail, "Jane Subject");
    }

    private static void AddUser(
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
    }

    public static IEndpointRouteBuilder MapPersonalDataApi(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapSentinelAuth();     // POST /auth/login
        endpoints.MapSentinelProfile();  // GET /profile/me
        endpoints.MapSentinelPrivacy();  // POST /sentinel-admin/privacy/export/{userId} | /erase/{userId}

        // The subject writes a note; it is stored ONLY as ciphertext under their key.
        endpoints.MapPost("/notes", async (
            HttpContext http, NotesVault vault, ISentinelCryptoShredder shredder, NoteRequest? request) =>
        {
            var principal = http.GetSentinelPrincipal();
            if (principal is null)
            {
                return Results.Unauthorized();
            }

            if (string.IsNullOrWhiteSpace(request?.Text))
            {
                return Results.BadRequest(new { error = "text is required" });
            }

            vault.Add(principal.SubjectId, await shredder.EncryptAsync(principal.SubjectId, request.Text));
            return Results.Ok(new { stored = vault.Count(principal.SubjectId) });
        });

        // SAMPLE-ONLY inspection endpoint: decrypts a user's notes so the README/tests can show
        // "readable before erasure, unrecoverable after". A real host would fence this behind
        // its own authorization and probably not expose it at all.
        endpoints.MapGet("/demo/notes/{userId:guid}", async (
            Guid userId, NotesVault vault, ISentinelCryptoShredder shredder) =>
        {
            var notes = new List<string>();
            foreach (var ciphertext in vault.Get(userId))
            {
                notes.Add(await shredder.TryDecryptAsync(userId, ciphertext) ?? "[unrecoverable]");
            }

            return Results.Ok(new { notes });
        });

        // SAMPLE-ONLY: walk the tamper-evident admin audit chain. null = intact.
        endpoints.MapGet("/demo/audit/verify", async (AuditService audit) =>
            Results.Ok(new { firstBrokenSequence = await audit.VerifyChainAsync(RealmId) }));

        // The retention sweep, on demand (production registers AddSentinelRetentionService and
        // lets the daily background sweep call the same method).
        endpoints.MapPost("/demo/retention/sweep", async (RetentionService retention) =>
        {
            var result = await retention.RunOnceAsync();
            return Results.Ok(new { result.SecurityEventsDeleted, result.AuditPayloadsRedacted });
        });

        return endpoints;
    }
}

public sealed record NoteRequest(string? Text);

/// <summary>Ciphertext-only storage: the vault never sees plaintext or keys.</summary>
public sealed class NotesVault
{
    private readonly Dictionary<Guid, List<string>> _notes = [];

    public void Add(Guid userId, string ciphertext)
    {
        lock (_notes)
        {
            (_notes.TryGetValue(userId, out var list) ? list : _notes[userId] = []).Add(ciphertext);
        }
    }

    public IReadOnlyList<string> Get(Guid userId)
    {
        lock (_notes)
        {
            return _notes.TryGetValue(userId, out var list) ? [.. list] : [];
        }
    }

    public int Count(Guid userId) => Get(userId).Count;
}
