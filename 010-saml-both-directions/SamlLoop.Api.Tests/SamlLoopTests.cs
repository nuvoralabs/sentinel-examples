using System.Net;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Nuvora.Nexus.Sentinel.Saml;
using SamlLoop.Api;
using Xunit;

namespace SamlLoop.Api.Tests;

/// <summary>
/// The article-010 walk, as executable assertions: the loopback round trip, both
/// metadata documents, and three ways the ACS says no — tampering, a swapped pin, replay.
/// </summary>
public class SamlLoopTests
{
    // ---------------------------------------------------------------------------------------
    // The loop closes
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Sp_initiated_round_trip_signs_the_browser_in()
    {
        await using var host = await SamlLoopTestHost.CreateAsync();

        var (jar, relayState, samlResponse) = await host.DriveToAcsAsync(returnUri: "/welcome");
        var acs = await host.PostAcsAsync(samlResponse, relayState, jar);

        // The ACS accepted the assertion: 302 to the requested return URL, session cookies set.
        acs.StatusCode.Should().Be(HttpStatusCode.Redirect);
        acs.Headers.Location!.ToString().Should().Be("/welcome");
        jar.Names.Should().Contain("sentinel_at");

        // The cookie session opens the landing endpoint.
        var welcomeRequest = new HttpRequestMessage(HttpMethod.Get, "/welcome");
        jar.Apply(welcomeRequest);
        (await host.Client.SendAsync(welcomeRequest)).StatusCode.Should().Be(HttpStatusCode.OK);

        // Both halves of the loop left their audit trace…
        host.Events.Events.Should().Contain(e => e.Kind == "saml.assertion_issued");
        host.Events.Events.Should().Contain(e => e.Kind == "saml.login_success");

        // …and the NameID is now linked to the pre-existing user (verified-email ladder).
        host.Federated.Links.Should().ContainSingle();
    }

    [Fact]
    public async Task Both_metadata_documents_are_served_and_the_idp_publishes_the_pinned_cert()
    {
        await using var host = await SamlLoopTestHost.CreateAsync();

        var sp = await host.Client.GetAsync("/auth/saml/metadata");
        sp.Content.Headers.ContentType!.MediaType.Should().Be("application/samlmetadata+xml");
        var spXml = await sp.Content.ReadAsStringAsync();
        spXml.Should().Contain("SPSSODescriptor")
            .And.Contain("WantAssertionsSigned=\"true\"")
            .And.Contain(SamlLoopComposition.SpEntityId);

        var idp = await host.Client.GetAsync("/saml/idp/metadata");
        var idpXml = await idp.Content.ReadAsStringAsync();
        idpXml.Should().Contain("IDPSSODescriptor").And.Contain(SamlLoopComposition.IdpEntityId);

        // The certificate in the IdP's metadata IS the one the SP side pinned: the loop's
        // trust anchor is exchanged out of band (metadata), never taken from a message.
        var pinnedBase64 = host.IdpConnection.IdpCertificatePem
            .Replace("-----BEGIN CERTIFICATE-----", "")
            .Replace("-----END CERTIFICATE-----", "")
            .Replace("\n", "").Replace("\r", "");
        idpXml.Replace("\n", "").Replace("\r", "").Should().Contain(pinnedBase64);
    }

    // ---------------------------------------------------------------------------------------
    // Three ways the ACS says no
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_tampered_assertion_fails_the_pinned_signature_check()
    {
        await using var host = await SamlLoopTestHost.CreateAsync();
        var (jar, relayState, samlResponse) = await host.DriveToAcsAsync();

        // Flip the asserted identity inside the signed XML — one character is enough.
        var xml = Encoding.UTF8.GetString(Convert.FromBase64String(samlResponse));
        var tampered = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            xml.Replace(SamlLoopComposition.UserEmail, "mallory@samlloop.sample")));

        var acs = await host.PostAcsAsync(tampered, relayState, jar);

        acs.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await acs.Content.ReadAsStringAsync()).Should().Contain("saml_failed");
        host.LastDenialReason().Should().Be("signature_invalid");

        // The rejection set no session cookies (the jar still only holds the ones the
        // in-host password login created before the loop started).
        acs.Headers.Contains("Set-Cookie").Should().BeFalse();
    }

    [Fact]
    public async Task An_authentic_assertion_fails_when_the_pin_no_longer_matches()
    {
        await using var host = await SamlLoopTestHost.CreateAsync();

        // Re-pin the SP-side connection to a different (attacker-ish) certificate. The IdP
        // still signs with its real key — but verification runs against THE PIN and nothing
        // else, embedded KeyInfo certificates included.
        using var otherKey = RSA.Create(2048);
        using var otherCert = SamlSignatures.CreateSigningCertificate(
            otherKey, "not-the-idp", DateTimeOffset.UtcNow);
        host.IdpConnection.IdpCertificatePem = otherCert.ExportCertificatePem();

        var (jar, relayState, samlResponse) = await host.DriveToAcsAsync();
        var acs = await host.PostAcsAsync(samlResponse, relayState, jar);

        acs.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        host.LastDenialReason().Should().Be("signature_invalid");
    }

    [Fact]
    public async Task A_replayed_response_is_rejected_the_second_time()
    {
        await using var host = await SamlLoopTestHost.CreateAsync();
        var (jar, relayState, samlResponse) = await host.DriveToAcsAsync();

        (await host.PostAcsAsync(samlResponse, relayState, jar))
            .StatusCode.Should().Be(HttpStatusCode.Redirect);

        // Same response, same RelayState, straight back at the ACS: single-use state.
        var replay = await host.PostAcsAsync(samlResponse, relayState, new CookieJar());
        replay.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await replay.Content.ReadAsStringAsync()).Should().Contain("saml_failed");
        host.LastDenialReason().Should().BeOneOf("state_invalid", "assertion_replayed");
    }
}
