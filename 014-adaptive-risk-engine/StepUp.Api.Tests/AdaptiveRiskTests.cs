using System.Net;
using System.Text.Json;
using FluentAssertions;
using Nuvora.Nexus.Sentinel.Ports;
using StepUp.Api;
using Xunit;

namespace StepUp.Api.Tests;

/// <summary>
/// The article-014 walk, as executable assertions: signal scores against the default
/// thresholds (step-up ≥ 40, block ≥ 80), the email-OTP step-up fallback, the opaque
/// block, and the new-device alert mail.
/// </summary>
public class AdaptiveRiskTests
{
    // ---------------------------------------------------------------------------------------
    // Below the step-up threshold
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_familiar_login_scores_zero_and_sails_through()
    {
        await using var host = await StepUpTestHost.CreateAsync();

        var login = await host.LoginAsync(StepUpWorld.NoraEmail, StepUpWorld.Password);
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        using var json = await StepUpTestHost.ReadJsonAsync(login);
        json.RootElement.GetProperty("status").GetString().Should().Be("ok");

        // Every login is scored — allow decisions land on the security ledger too.
        var ledger = await host.AuditStore.GetSecurityEventsForUserAsync(StepUpWorld.NoraId, 50);
        ledger.Should().Contain(e => e.Kind == "risk.evaluated");
        host.Mailer.Sent.Should().BeEmpty();
    }

    [Fact]
    public async Task A_new_device_alerts_by_mail_but_30_points_do_not_step_up()
    {
        await using var host = await StepUpTestHost.CreateAsync();

        // new_device contributes 30 < 40: the login completes…
        var login = await host.LoginAsync(
            StepUpWorld.NoraEmail, StepUpWorld.Password, deviceFingerprint: "fp-laptop");
        using (var json = await StepUpTestHost.ReadJsonAsync(login))
        {
            json.RootElement.GetProperty("status").GetString().Should().Be("ok");
        }

        // …but the user hears about it: a security_alert mail and a login.new_device event.
        var alert = host.Mailer.Sent.Should()
            .ContainSingle(m => m.Kind == SentinelMailKinds.SecurityAlert).Subject;
        alert.To.Should().Be(StepUpWorld.NoraEmail);
        alert.Data["alert"].Should().Be("new_device");
        host.Events.Events.Should().ContainSingle(e => e.Kind == "login.new_device");

        // The same device again is known: no second alert.
        await host.LoginAsync(StepUpWorld.NoraEmail, StepUpWorld.Password, deviceFingerprint: "fp-laptop");
        host.Mailer.Sent.Count(m => m.Kind == SentinelMailKinds.SecurityAlert).Should().Be(1);
    }

    // ---------------------------------------------------------------------------------------
    // Step-up with the email-OTP fallback
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task A_listed_ip_forces_step_up_and_email_otp_completes_it()
    {
        await using var host = await StepUpTestHost.CreateAsync();

        // ip_reputation contributes 50 ≥ 40: step-up. Nora has no TOTP, so the fallback
        // sends a one-time code to her verified email — the password alone minted NOTHING.
        var login = await host.LoginAsync(StepUpWorld.NoraEmail, StepUpWorld.Password, ip: StepUpWorld.BadIp);
        login.StatusCode.Should().Be(HttpStatusCode.OK);
        string pending;
        using (var json = await StepUpTestHost.ReadJsonAsync(login))
        {
            json.RootElement.GetProperty("status").GetString().Should().Be("mfa_required");
            json.RootElement.GetProperty("factor").GetString().Should().Be("email_otp");
            json.RootElement.TryGetProperty("accessToken", out _).Should().BeFalse();
            pending = json.RootElement.GetProperty("mfaPendingToken").GetString()!;
        }

        host.Events.Events.Should().Contain(e => e.Kind == "risk.stepup");
        var mail = host.Mailer.Sent.Should()
            .ContainSingle(m => m.Kind == SentinelMailKinds.EmailOtp).Subject;
        mail.To.Should().Be(StepUpWorld.NoraEmail);

        // A wrong code does not complete the login…
        (await host.VerifyEmailOtpAsync(pending, "000000")).StatusCode
            .Should().Be(HttpStatusCode.Unauthorized);

        // …the mailed code does.
        var verify = await host.VerifyEmailOtpAsync(pending, mail.Data["code"]);
        verify.StatusCode.Should().Be(HttpStatusCode.OK);
        using (var json = await StepUpTestHost.ReadJsonAsync(verify))
        {
            json.RootElement.GetProperty("status").GetString().Should().Be("ok");
            json.RootElement.GetProperty("accessToken").GetString().Should().NotBeNullOrEmpty();
        }
    }

    [Fact]
    public async Task The_custom_watchlist_signal_steps_victor_up_from_anywhere()
    {
        await using var host = await StepUpTestHost.CreateAsync();

        // Clean IP, no device oddities — but the app's own signal contributes 40.
        var login = await host.LoginAsync(StepUpWorld.VictorEmail, StepUpWorld.Password);
        using var json = await StepUpTestHost.ReadJsonAsync(login);
        json.RootElement.GetProperty("status").GetString().Should().Be("mfa_required");
        json.RootElement.GetProperty("factor").GetString().Should().Be("email_otp");

        // The reason lands verbatim on the risk.evaluated ledger row's contribution list.
        var ledger = await host.AuditStore.GetSecurityEventsForUserAsync(StepUpWorld.VictorId, 50);
        var evaluated = ledger.Last(e => e.Kind == "risk.evaluated");
        evaluated.DataJson.Should().Contain("fraud watchlist");
    }

    // ---------------------------------------------------------------------------------------
    // The block threshold
    // ---------------------------------------------------------------------------------------

    [Fact]
    public async Task Stacked_signals_block_indistinguishably_from_a_wrong_password()
    {
        await using var host = await StepUpTestHost.CreateAsync();

        // ip_reputation 50 + new_device 30 = 80 ≥ 80: Block. The caller sees the SAME
        // 401 invalid_credentials as a wrong password — byte-identical, no oracle.
        var blocked = await host.LoginAsync(
            StepUpWorld.NoraEmail, StepUpWorld.Password, ip: StepUpWorld.BadIp, deviceFingerprint: "fp-new");
        var wrongPassword = await host.LoginAsync(StepUpWorld.NoraEmail, "not-the-password");

        blocked.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await blocked.Content.ReadAsStringAsync())
            .Should().Be(await wrongPassword.Content.ReadAsStringAsync())
            .And.Contain("invalid_credentials");

        // The distinction lives in the audit stream, not the response.
        host.Events.Events.Should().Contain(e => e.Kind == "risk.blocked");
    }
}
