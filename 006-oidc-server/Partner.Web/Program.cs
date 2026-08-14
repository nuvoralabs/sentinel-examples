// Sample 006 — the relying party. A plain OIDC client app (no Sentinel packages): it redirects
// to the IdP's authorize endpoint, exchanges code + PKCE for tokens, and shows the identity.
// Thin composition: everything interesting lives in PartnerComposition, which the tests reuse.

using Partner.Web;

var builder = WebApplication.CreateBuilder(args);

// Defaults match a local two-app run (IdP.Api on :5006, this app on :5007); the IdP's seeded
// client registration lists the local callback too, so `dotnet run` on both is enough.
builder.Services.AddPartnerWeb(o => builder.Configuration.GetSection("Partner").Bind(o));

var app = builder.Build();

app.MapPartnerWeb();

await app.RunAsync();
