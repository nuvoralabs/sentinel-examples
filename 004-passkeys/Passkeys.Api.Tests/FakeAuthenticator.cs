// Copied from the Sentinel library's own HTTP test suite
// (tests/Nuvora.Nexus.Sentinel.Tests.Http/FakeAuthenticator.cs) — the canonical way to drive
// the passkey endpoints without a browser. Only the namespace differs.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Nuvora.Nexus.Sentinel.Tokens;

namespace Passkeys.Api.Tests;

/// <summary>
/// A software WebAuthn authenticator for tests. Fido2NetLib has no public conformance/test
/// helper package, but a full fake is feasible because Sentinel registers with attestation
/// <c>none</c> (no attestation signature to forge — the attStmt is empty by spec) and
/// assertions just need a real ECDSA P-256 signature over authenticatorData || SHA-256(clientDataJSON)
/// with a key we generate ourselves. This exercises the genuine Fido2NetLib verification path
/// end-to-end: CBOR parsing, COSE key decoding, rpIdHash/origin/challenge checks, signature
/// verification, and sign-count bookkeeping.
/// </summary>
public sealed class FakeAuthenticator : IDisposable
{
    private const byte FlagUserPresent = 0x01;
    private const byte FlagUserVerified = 0x04;
    private const byte FlagAttestedCredentialData = 0x40;

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string _rpId;
    private readonly string _origin;

    public FakeAuthenticator(string rpId, string origin, bool userVerification = true)
    {
        _rpId = rpId;
        _origin = origin;
        UserVerification = userVerification;
    }

    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(32);

    /// <summary>Whether this authenticator sets the UV flag in its responses (decides uv_capable).</summary>
    public bool UserVerification { get; set; }

    /// <summary>Counter reported on the next assertion; tests set it directly to fake clones/regressions.</summary>
    public uint SignCount { get; set; }

    /// <summary>The user handle returned with assertions (set from the registration options' user.id).</summary>
    public byte[] UserHandle { get; set; } = [];

    /// <summary>Builds the browser-shaped registration payload for the given create options JSON.</summary>
    public object CreateAttestation(JsonElement createOptions)
    {
        var challenge = createOptions.GetProperty("challenge").GetString()!;
        UserHandle = Base64Url.Decode(createOptions.GetProperty("user").GetProperty("id").GetString()!);

        var clientDataJson = ClientDataJson("webauthn.create", challenge);
        var flags = (byte)(FlagUserPresent | FlagAttestedCredentialData | (UserVerification ? FlagUserVerified : 0));
        var authData = BuildAuthData(flags, attestedCredential: true);

        // attestationObject = CBOR {"fmt":"none","attStmt":{},"authData":...} (canonical order).
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString("none");
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteTextString("authData");
        writer.WriteByteString(authData);
        writer.WriteEndMap();

        return new
        {
            id = Base64Url.Encode(CredentialId),
            rawId = Base64Url.Encode(CredentialId),
            type = "public-key",
            response = new
            {
                attestationObject = Base64Url.Encode(writer.Encode()),
                clientDataJSON = Base64Url.Encode(clientDataJson),
            },
            clientExtensionResults = new { },
        };
    }

    /// <summary>Builds the browser-shaped assertion payload for the given assertion options JSON.</summary>
    public object CreateAssertion(JsonElement assertionOptions)
    {
        var challenge = assertionOptions.GetProperty("challenge").GetString()!;
        var clientDataJson = ClientDataJson("webauthn.get", challenge);
        var flags = (byte)(FlagUserPresent | (UserVerification ? FlagUserVerified : 0));
        var authData = BuildAuthData(flags, attestedCredential: false);

        var signedPayload = new byte[authData.Length + 32];
        authData.CopyTo(signedPayload, 0);
        SHA256.HashData(clientDataJson).CopyTo(signedPayload, authData.Length);
        var signature = _key.SignData(
            signedPayload, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        return new
        {
            id = Base64Url.Encode(CredentialId),
            rawId = Base64Url.Encode(CredentialId),
            type = "public-key",
            response = new
            {
                authenticatorData = Base64Url.Encode(authData),
                clientDataJSON = Base64Url.Encode(clientDataJson),
                signature = Base64Url.Encode(signature),
                userHandle = UserHandle.Length > 0 ? Base64Url.Encode(UserHandle) : null,
            },
            clientExtensionResults = new { },
        };
    }

    public void Dispose() => _key.Dispose();

    private byte[] ClientDataJson(string type, string challenge) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            type,
            challenge,
            origin = _origin,
        }));

    private byte[] BuildAuthData(byte flags, bool attestedCredential)
    {
        using var buffer = new MemoryStream();
        buffer.Write(SHA256.HashData(Encoding.UTF8.GetBytes(_rpId)));
        buffer.WriteByte(flags);
        Span<byte> counter = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(counter, SignCount);
        buffer.Write(counter);

        if (attestedCredential)
        {
            buffer.Write(new byte[16]); // AAGUID: zero, as anonymized "none" attestations do.
            Span<byte> length = stackalloc byte[2];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)CredentialId.Length);
            buffer.Write(length);
            buffer.Write(CredentialId);
            buffer.Write(CosePublicKey());
        }

        return buffer.ToArray();
    }

    /// <summary>COSE_Key for ES256: {1: EC2, 3: -7, -1: P-256, -2: x, -3: y} in canonical order.</summary>
    private byte[] CosePublicKey()
    {
        var parameters = _key.ExportParameters(includePrivateParameters: false);
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        writer.WriteInt32(3);
        writer.WriteInt32(-7);
        writer.WriteInt32(-1);
        writer.WriteInt32(1);
        writer.WriteInt32(-2);
        writer.WriteByteString(Pad32(parameters.Q.X!));
        writer.WriteInt32(-3);
        writer.WriteByteString(Pad32(parameters.Q.Y!));
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] Pad32(byte[] value)
    {
        if (value.Length == 32)
        {
            return value;
        }

        var padded = new byte[32];
        value.CopyTo(padded, 32 - value.Length);
        return padded;
    }
}
