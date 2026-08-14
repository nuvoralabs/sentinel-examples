using Clinic.Login.Api;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Nuvora.Nexus.Sentinel.AspNetCore.Endpoints;

namespace Clinic.Login.Api.Tests;

/// <summary>
/// In-memory host for the sample: the SAME composition as Program.cs (services from
/// <see cref="ClinicLoginServiceCollectionExtensions.AddClinicLoginApi"/>, same pipeline, same
/// seed), served through Microsoft.AspNetCore.TestHost.
/// </summary>
internal static class ClinicTestHost
{
    public static async Task<IHost> CreateAsync()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services => services.AddClinicLoginApi())
                .Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapSentinelAuth();
                        endpoints.MapSentinelProfile();
                        endpoints.MapClinicDashboard();
                    });
                }))
            .StartAsync();

        await ClinicDemo.SeedAsync(host.Services);
        return host;
    }
}

/// <summary>
/// Manual cookie jar (pattern borrowed from the library's own HTTP surface tests): TestServer's
/// HttpClient does no cookie handling, which is exactly right here — every Set-Cookie is
/// inspected explicitly and replayed on purpose, the way the cookie-transport assertions need.
/// </summary>
internal sealed class CookieJar
{
    private readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

    public string? this[string name] => _cookies.TryGetValue(name, out var value) ? value : null;

    public IReadOnlyCollection<string> Names => _cookies.Keys;

    public void Update(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var headers))
        {
            return;
        }

        foreach (var header in headers)
        {
            var pair = header.Split(';')[0];
            var eq = pair.IndexOf('=');
            var name = pair[..eq];
            var value = pair[(eq + 1)..];
            if (value.Length == 0)
            {
                _cookies.Remove(name); // Deletion cookie ("name=; expires=1970...").
            }
            else
            {
                _cookies[name] = value;
            }
        }
    }

    public void Apply(HttpRequestMessage request)
    {
        if (_cookies.Count > 0)
        {
            request.Headers.Add("Cookie", string.Join("; ", _cookies.Select(kv => $"{kv.Key}={kv.Value}")));
        }
    }
}
