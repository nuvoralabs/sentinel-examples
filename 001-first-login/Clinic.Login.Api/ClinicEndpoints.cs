using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Nuvora.Nexus.Sentinel.AspNetCore;

namespace Clinic.Login.Api;

public static class ClinicEndpoints
{
    /// <summary>
    /// The app's own protected endpoint. The Sentinel authentication handler has
    /// already validated the cookie (or rejected it — including the CSRF double-submit check on
    /// unsafe methods) by the time this runs; the endpoint only asks for the principal.
    /// </summary>
    public static IEndpointRouteBuilder MapClinicDashboard(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/clinic/dashboard", (HttpContext http) =>
        {
            // No principal means no valid session cookie: the request never authenticated.
            var principal = http.GetSentinelPrincipal();
            if (principal is null)
            {
                return Results.Unauthorized();
            }

            return Results.Ok(new
            {
                clinician = principal.SubjectId,
                organizationId = principal.OrganizationId,
                appointments = new[]
                {
                    new { time = "09:00", patient = "M. Okafor", reason = "Annual physical" },
                    new { time = "09:30", patient = "J. Lindqvist", reason = "Follow-up: labs" },
                    new { time = "10:15", patient = "A. Beaumont", reason = "Vaccination" },
                },
            });
        });

        return endpoints;
    }
}
