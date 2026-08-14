using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Base64Url = System.Buffers.Text.Base64Url;

namespace Partner.Web;

/// <summary>
/// How the relying party finds the IdP. Defaults match IdP.Api's seeded client registration;
/// Program.cs / tests can reconfigure.
/// </summary>
public sealed class PartnerOptions
{
    /// <summary>Browser-facing base URL of the authorization server — where /signin redirects to. Defaults to IdP.Api's local run address.</summary>
    public string IdpAuthority { get; set; } = "http://localhost:5006";

    /// <summary>
    /// The <c>iss</c> the RP expects in ID tokens. A logical identifier, deliberately separate
    /// from <see cref="IdpAuthority"/>: the same IdP answers on localhost in dev and behind its
    /// public URL in prod, while its issuer string stays constant.
    /// </summary>
    public string ExpectedIssuer { get; set; } = "https://idp.sample";

    public string ClientId { get; set; } = "partner-web";

    /// <summary>Must be registered VERBATIM on the client at the IdP — exact-match, no prefixes.</summary>
    public string RedirectUri { get; set; } = "http://localhost:5007/callback";

    public string Scopes { get; set; } = "openid profile email offline_access";
}

/// <summary>What the RP keeps per signed-in browser: the identity it learned plus the tokens.</summary>
public sealed record PartnerSession(
    string Subject, string? Email, string? Name, string AccessToken, string? RefreshToken);

/// <summary>
/// A deliberately hand-rolled OIDC relying party: /signin starts the code+PKCE dance against the
/// IdP's authorize endpoint, /callback exchanges the code over the back channel, /me shows the
/// signed-in identity. Sentinel's AS surface is plain OAuth2/OIDC, so THIS is all a
/// partner app needs — no Sentinel packages involved.
/// </summary>
public static class PartnerComposition
{
    /// <summary>Named HttpClient for BACK-CHANNEL calls (token, userinfo) — tests point it at the IdP TestServer.</summary>
    public const string IdpHttpClient = "idp";

    private const string StateCookie = "partner_oidc_state";
    private const string SessionCookie = "partner_session";

    public static IServiceCollection AddPartnerWeb(
        this IServiceCollection services, Action<PartnerOptions>? configure = null)
    {
        if (configure is not null)
        {
            services.Configure(configure);
        }
        else
        {
            services.AddOptions<PartnerOptions>();
        }

        services.AddSingleton<ConcurrentDictionary<string, PartnerSession>>();
        services.AddHttpClient(IdpHttpClient, (sp, client) =>
            client.BaseAddress = new Uri(sp.GetRequiredService<IOptions<PartnerOptions>>().Value.IdpAuthority));

        return services;
    }

    public static IEndpointRouteBuilder MapPartnerWeb(this IEndpointRouteBuilder endpoints)
    {
        // -------------------------------------------------------------------------------------
        // 1) /signin — redirect the browser to the IdP's authorize endpoint with state, nonce
        //    and a PKCE S256 challenge (PKCE is REQUIRED for public clients). The verifier
        //    stays on our side, in a short-lived httpOnly cookie.
        // -------------------------------------------------------------------------------------
        endpoints.MapGet("/signin", (HttpContext http, IOptions<PartnerOptions> options) =>
        {
            var o = options.Value;
            var state = RandomToken();
            var nonce = RandomToken();
            var verifier = RandomToken();
            var challenge = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

            http.Response.Cookies.Append(StateCookie,
                Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(new { state, nonce, verifier })),
                new CookieOptions { HttpOnly = true, MaxAge = TimeSpan.FromMinutes(5) });

            var authorizeUrl = $"{o.IdpAuthority}/oidc/authorize"
                + $"?client_id={Uri.EscapeDataString(o.ClientId)}"
                + $"&redirect_uri={Uri.EscapeDataString(o.RedirectUri)}"
                + "&response_type=code"
                + $"&scope={Uri.EscapeDataString(o.Scopes)}"
                + $"&state={Uri.EscapeDataString(state)}"
                + $"&nonce={Uri.EscapeDataString(nonce)}"
                + $"&code_challenge={Uri.EscapeDataString(challenge)}"
                + "&code_challenge_method=S256";
            return Results.Redirect(authorizeUrl);
        });

        // -------------------------------------------------------------------------------------
        // 2) /callback — the browser lands back here with ?code&state. Validate state, exchange
        //    the code + PKCE verifier for tokens over the BACK channel, sanity-check the ID
        //    token, load userinfo with the access token, establish our own session.
        // -------------------------------------------------------------------------------------
        endpoints.MapGet("/callback", async (
            string? code,
            string? state,
            string? error,
            HttpContext http,
            IHttpClientFactory httpClients,
            IOptions<PartnerOptions> options,
            ConcurrentDictionary<string, PartnerSession> sessions,
            CancellationToken ct) =>
        {
            if (error is not null)
            {
                return Results.BadRequest(new { error }); // e.g. access_denied from consent
            }

            var stashed = ReadStateCookie(http);
            http.Response.Cookies.Delete(StateCookie);
            if (code is null || stashed is null || state != stashed.State)
            {
                return Results.BadRequest(new { error = "state_mismatch" });
            }

            var o = options.Value;
            var idp = httpClients.CreateClient(IdpHttpClient);

            var tokenResponse = await idp.PostAsync("/oidc/token", new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["client_id"] = o.ClientId,
                    ["code"] = code,
                    ["redirect_uri"] = o.RedirectUri,
                    ["code_verifier"] = stashed.Verifier, // PKCE proof
                }), ct);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                return Results.BadRequest(new { error = "token_exchange_failed" });
            }

            string accessToken;
            string? refreshToken;
            string idToken;
            using (var tokens = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync(ct)))
            {
                accessToken = tokens.RootElement.GetProperty("access_token").GetString()!;
                idToken = tokens.RootElement.GetProperty("id_token").GetString()!;
                refreshToken = tokens.RootElement.TryGetProperty("refresh_token", out var rt)
                    ? rt.GetString()
                    : null; // present because we asked for offline_access
            }

            // ID-token sanity checks (iss/aud/nonce). A production RP also validates the RS256
            // signature against the discovery document's jwks_uri — omitted here to keep the
            // protocol shape in one screen; the tests cover signatures via Sentinel's own suite.
            using (var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(idToken.Split('.')[1])))
            {
                var claims = payload.RootElement;
                if (claims.GetProperty("iss").GetString() != o.ExpectedIssuer
                    || claims.GetProperty("aud").GetString() != o.ClientId
                    || claims.GetProperty("nonce").GetString() != stashed.Nonce)
                {
                    return Results.BadRequest(new { error = "id_token_rejected" });
                }
            }

            // Prove the access token by using it: userinfo is the canonical consumer.
            var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "/oidc/userinfo");
            userInfoRequest.Headers.Authorization = new("Bearer", accessToken);
            var userInfoResponse = await idp.SendAsync(userInfoRequest, ct);
            if (!userInfoResponse.IsSuccessStatusCode)
            {
                return Results.BadRequest(new { error = "userinfo_failed" });
            }

            PartnerSession session;
            using (var userInfo = JsonDocument.Parse(await userInfoResponse.Content.ReadAsStringAsync(ct)))
            {
                session = new PartnerSession(
                    userInfo.RootElement.GetProperty("sub").GetString()!,
                    userInfo.RootElement.TryGetProperty("email", out var email) ? email.GetString() : null,
                    userInfo.RootElement.TryGetProperty("name", out var name) ? name.GetString() : null,
                    accessToken,
                    refreshToken);
            }

            var sessionId = RandomToken();
            sessions[sessionId] = session;
            http.Response.Cookies.Append(SessionCookie, sessionId, new CookieOptions { HttpOnly = true });
            return Results.Redirect("/me");
        });

        // 3) /me — the signed-in identity, from the RP's own session.
        endpoints.MapGet("/me", (HttpContext http, ConcurrentDictionary<string, PartnerSession> sessions) =>
            TryGetSession(http, sessions, out var session)
                ? Results.Ok(new
                {
                    sub = session!.Subject,
                    email = session.Email,
                    name = session.Name,
                    hasRefreshToken = session.RefreshToken is not null,
                })
                : Results.Unauthorized());

        // -------------------------------------------------------------------------------------
        // 4) /refresh — the refresh grant: rotate the stored refresh token for a
        //    fresh access token, no browser round-trip to the IdP.
        // -------------------------------------------------------------------------------------
        endpoints.MapPost("/refresh", async (
            HttpContext http,
            IHttpClientFactory httpClients,
            IOptions<PartnerOptions> options,
            ConcurrentDictionary<string, PartnerSession> sessions,
            CancellationToken ct) =>
        {
            if (!TryGetSession(http, sessions, out var session) || session!.RefreshToken is null)
            {
                return Results.Unauthorized();
            }

            var idp = httpClients.CreateClient(IdpHttpClient);
            var response = await idp.PostAsync("/oidc/token", new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["client_id"] = options.Value.ClientId,
                    ["refresh_token"] = session.RefreshToken,
                }), ct);
            if (!response.IsSuccessStatusCode)
            {
                return Results.BadRequest(new { error = "refresh_failed" });
            }

            using var tokens = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            var rotated = session with
            {
                AccessToken = tokens.RootElement.GetProperty("access_token").GetString()!,
                // Refresh tokens ROTATE on every use — store the replacement, the old one
                // is now a tripwire (its reuse revokes the whole family).
                RefreshToken = tokens.RootElement.GetProperty("refresh_token").GetString(),
            };
            sessions[http.Request.Cookies[SessionCookie]!] = rotated;
            return Results.Ok(new { refreshed = true });
        });

        return endpoints;
    }

    private static bool TryGetSession(
        HttpContext http, ConcurrentDictionary<string, PartnerSession> sessions, out PartnerSession? session)
    {
        session = null;
        return http.Request.Cookies.TryGetValue(SessionCookie, out var id)
            && sessions.TryGetValue(id, out session);
    }

    private static StashedState? ReadStateCookie(HttpContext http)
    {
        if (!http.Request.Cookies.TryGetValue(StateCookie, out var raw))
        {
            return null;
        }

        try
        {
            using var json = JsonDocument.Parse(Base64Url.DecodeFromChars(raw));
            return new StashedState(
                json.RootElement.GetProperty("state").GetString()!,
                json.RootElement.GetProperty("nonce").GetString()!,
                json.RootElement.GetProperty("verifier").GetString()!);
        }
        catch (Exception e) when (e is JsonException or FormatException)
        {
            return null;
        }
    }

    private static string RandomToken() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    private sealed record StashedState(string State, string Nonce, string Verifier);
}
