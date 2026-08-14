using System.Net;
using System.Text.Json;
using FluentAssertions;
using Ledger.Api;
using Nuvora.Nexus.Sentinel.Audit;
using Nuvora.Nexus.Sentinel.Privacy;
using Xunit;

namespace Ledger.Api.Tests;

/// <summary>
/// The article-012 walk, as executable assertions: mutations append and chain,
/// tampering (field or payload) flips chainIntact, deletion is a detected gap, and
/// redaction preserves verification.
/// </summary>
public class AuditChainTests
{
    // ---------------------------------------------------------------------------------------
    // Appending + linking
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Admin_mutations_append_linked_entries_and_the_chain_verifies()
    {
        await using var host = await LedgerTestHost.CreateAsync();
        var admin = await host.LoginAsync(LedgerWorld.AdminEmail);

        await host.MutateTwiceAsync(admin);

        using var audit = await host.GetAuditAsync(admin);
        var root = audit.RootElement;

        root.GetProperty("chainIntact").GetBoolean().Should().BeTrue();
        root.GetProperty("firstBrokenSequence").ValueKind.Should().Be(JsonValueKind.Null);

        var entries = root.GetProperty("entries").EnumerateArray().ToArray();
        entries.Should().HaveCount(2);

        entries[0].GetProperty("action").GetString().Should().Be("user.suspended");
        entries[0].GetProperty("sequence").GetInt64().Should().Be(1);
        entries[0].GetProperty("previousHash").GetString().Should().Be(AdminAuditChain.GenesisHash);
        entries[0].GetProperty("actorId").GetGuid().Should().Be(LedgerWorld.AdminId);
        entries[0].GetProperty("targetId").GetGuid().Should().Be(LedgerWorld.TargetId);

        entries[1].GetProperty("action").GetString().Should().Be("user.reactivated");
        entries[1].GetProperty("previousHash").GetString()
            .Should().Be(entries[0].GetProperty("entryHash").GetString(),
                "each entry's hash is the next entry's ancestor");
    }

    [Fact]
    public async Task The_auditor_can_read_the_ledger_but_cannot_mutate()
    {
        await using var host = await LedgerTestHost.CreateAsync();
        var admin = await host.LoginAsync(LedgerWorld.AdminEmail);
        var auditor = await host.LoginAsync(LedgerWorld.AuditorEmail);

        await host.MutateTwiceAsync(admin);

        // sentinel:global:audit_read opens GET /sentinel-admin/audit …
        using var audit = await host.GetAuditAsync(auditor);
        audit.RootElement.GetProperty("entries").GetArrayLength().Should().Be(2);

        // … and nothing else: the same bearer is refused a mutation, with the stable code.
        var denied = await host.SendAsync(auditor, HttpMethod.Post,
            $"/sentinel-admin/orgs/{LedgerWorld.OrgId}/users/{LedgerWorld.TargetId}/suspend");
        denied.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await denied.Content.ReadAsStringAsync()).Should().Contain("admin_scope");
    }

    // ---------------------------------------------------------------------------------------
    // Tamper detection
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Rewriting_a_stored_entry_field_flips_chainIntact()
    {
        await using var host = await LedgerTestHost.CreateAsync();
        var admin = await host.LoginAsync(LedgerWorld.AdminEmail);
        await host.MutateTwiceAsync(admin);

        // Reach into storage the way a hostile DBA would: rewrite WHAT happened.
        var entries = await host.AuditStore.GetAdminEntriesAsync(LedgerWorld.RealmId, fromSequence: 1, limit: 10);
        entries[0].Action = "role.grant_removed";

        using var audit = await host.GetAuditAsync(admin);
        audit.RootElement.GetProperty("chainIntact").GetBoolean().Should().BeFalse();
        audit.RootElement.GetProperty("firstBrokenSequence").GetInt64().Should().Be(1);
    }

    [Fact]
    public async Task Rewriting_only_the_payload_is_caught_by_the_digest_not_the_chain_hash()
    {
        await using var host = await LedgerTestHost.CreateAsync();
        var admin = await host.LoginAsync(LedgerWorld.AdminEmail);
        await host.MutateTwiceAsync(admin);

        // Subtler: leave every chained field alone and forge only the before-image. The
        // pre-image commits to the payload BY DIGEST, so the chain hash still matches —
        // the stored-digest check is what catches this one.
        var entries = await host.AuditStore.GetAdminEntriesAsync(LedgerWorld.RealmId, fromSequence: 1, limit: 10);
        entries[1].AfterJson = """{"status":"Active","note":"nothing happened here"}""";

        using var audit = await host.GetAuditAsync(admin);
        audit.RootElement.GetProperty("chainIntact").GetBoolean().Should().BeFalse();
        audit.RootElement.GetProperty("firstBrokenSequence").GetInt64().Should().Be(2);
    }

    [Fact]
    public async Task Deleting_an_entry_is_detected_as_a_sequence_gap()
    {
        await using var host = await LedgerTestHost.CreateAsync();
        var admin = await host.LoginAsync(LedgerWorld.AdminEmail);
        await host.MutateTwiceAsync(admin);
        await host.MutateTwiceAsync(admin); // four entries

        var entries = await host.AuditStore.GetAdminEntriesAsync(LedgerWorld.RealmId, fromSequence: 1, limit: 10);
        entries.Should().HaveCount(4);

        // AdminAuditChain.Verify works on any fragment: drop entry 3 and the walk
        // breaks exactly there (0-based index 2).
        var withoutThird = new[] { entries[0], entries[1], entries[3] };
        AdminAuditChain.Verify(withoutThird).Should().Be(2);
    }

    // ---------------------------------------------------------------------------------------
    // Redaction
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Redacting_payloads_preserves_the_chain_because_digests_survive()
    {
        await using var host = await LedgerTestHost.CreateAsync();
        var admin = await host.LoginAsync(LedgerWorld.AdminEmail);
        await host.MutateTwiceAsync(admin);

        // Retention/erasure redaction: null the payloads, keep sequence, hashes AND digests.
        var redacted = await ((IRetentionStore)host.AuditStore)
            .RedactAdminAuditPayloadsForUserAsync(LedgerWorld.TargetId);
        redacted.Should().Be(2);

        using var audit = await host.GetAuditAsync(admin);
        var root = audit.RootElement;

        root.GetProperty("chainIntact").GetBoolean()
            .Should().BeTrue("the pre-image commits to payload digests, not payload bytes");
        foreach (var entry in root.GetProperty("entries").EnumerateArray())
        {
            entry.GetProperty("after").ValueKind.Should().Be(JsonValueKind.Null);
        }

        // But forging a payload back in cannot work: the digest no longer matches.
        var entries = await host.AuditStore.GetAdminEntriesAsync(LedgerWorld.RealmId, fromSequence: 1, limit: 10);
        entries[0].BeforeJson = """{"status":"Active"}""";
        using var reforged = await host.GetAuditAsync(admin);
        reforged.RootElement.GetProperty("chainIntact").GetBoolean().Should().BeFalse();
    }
}
