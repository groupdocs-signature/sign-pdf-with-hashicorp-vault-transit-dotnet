using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace VaultCustomSignHash;

/// <summary>
/// The latest version of a Transit key and its public key in PEM format.
/// </summary>
public sealed record VaultKey(int Version, string PublicKeyPem);

/// <summary>
/// Minimal HTTP client for the HashiCorp Vault Transit secrets engine. API:
/// https://developer.hashicorp.com/vault/api-docs/secret/transit
/// </summary>
public sealed class VaultTransitClient : IDisposable
{
    private readonly HttpClient _httpClient;

    /// <summary>
    /// Creates a client that sends every request to one Vault with one token.
    /// </summary>
    /// <remarks>
    /// The token goes in the <c>X-Vault-Token</c> header of every request. With the local
    /// dev Vault from <c>docker-compose.yml</c> this is the root token
    /// <c>dev-only-token</c>; a real application uses a short-lived token from an auth
    /// method such as AppRole, limited by a policy to reading the key and signing with it.
    /// Use HTTPS outside a local test.
    /// </remarks>
    /// <param name="vaultAddress">Vault address, for example
    /// <c>http://localhost:8200</c>.</param>
    /// <param name="vaultToken">Vault token used for all requests.</param>
    public VaultTransitClient(string vaultAddress, string vaultToken)
    {
        _httpClient = new HttpClient { BaseAddress = new Uri(vaultAddress) };
        _httpClient.DefaultRequestHeaders.Add("X-Vault-Token", vaultToken);
    }

    /// <summary>
    /// Reads the latest version of a Transit key and its public key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Calls <c>GET /v1/transit/keys/{keyName}</c>. Vault returns a map of all key
    /// versions with a <c>public_key</c> (PEM) for each, plus <c>latest_version</c>; this
    /// method returns the latest one. The private key is never part of the answer.
    /// </para>
    /// <para>
    /// Returns <c>null</c> when Vault answers 404: the key does not exist or Transit is
    /// not enabled. Any other error (for example 403 when the token may not read the key)
    /// throws with Vault's own message.
    /// </para>
    /// <para>
    /// The version matters: a certificate holds one public key, so the same version must
    /// be used for the certificate and for every sign request. After a key rotation the
    /// latest version changes and so does its public key.
    /// </para>
    /// </remarks>
    /// <param name="keyName">Transit key name.</param>
    /// <returns>The latest version and its public key, or <c>null</c> if there is no
    /// key.</returns>
    public async Task<VaultKey?> ReadKeyAsync(string keyName)
    {
        using HttpResponseMessage response =
            await _httpClient.GetAsync($"/v1/transit/keys/{keyName}");
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
        await EnsureSuccessAsync(response);

        using JsonDocument json =
            JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement data = json.RootElement.GetProperty("data");
        int version = data.GetProperty("latest_version").GetInt32();
        string publicKeyPem = data.GetProperty("keys").GetProperty(version.ToString())
                .GetProperty("public_key").GetString()
            ?? throw new InvalidOperationException(
                $"Vault returned no public key for '{keyName}' version {version}.");
        return new VaultKey(version, publicKeyPem);
    }

    /// <summary>
    /// Enables the Transit secrets engine at <c>transit/</c>.
    /// </summary>
    /// <remarks>
    /// Calls <c>POST /v1/sys/mounts/transit</c> with <c>type = transit</c>. If Transit is
    /// already enabled, Vault answers 400 "path is already in use"; that answer is treated
    /// as success, any other error throws. This is an administrator action: it needs a
    /// token with rights on <c>sys/mounts</c>, which the root dev token has and a signing
    /// app should not have.
    /// </remarks>
    public async Task EnableTransitAsync()
    {
        using HttpResponseMessage response = await _httpClient.PostAsJsonAsync(
            "/v1/sys/mounts/transit", new { type = "transit" });
        if (response.StatusCode == HttpStatusCode.BadRequest
            && (await response.Content.ReadAsStringAsync())
                .Contains("path is already in use"))
        {
            return;
        }
        await EnsureSuccessAsync(response);
    }

    /// <summary>
    /// Creates a Transit key whose private part is generated inside Vault.
    /// </summary>
    /// <remarks>
    /// Calls <c>POST /v1/transit/keys/{keyName}</c> with the key type, for example
    /// <c>rsa-2048</c>. The key is created with <c>exportable = false</c> (Vault's
    /// default), so no API returns the private key: <c>transit/export/signing-key</c>
    /// answers 400 "private key material is not exportable". Creating a key that already
    /// exists returns the existing key unchanged. Like <see cref="EnableTransitAsync"/>,
    /// this is an administrator action.
    /// </remarks>
    /// <param name="keyName">Name of the new key.</param>
    /// <param name="keyType">Vault key type, for example <c>rsa-2048</c>.</param>
    public async Task CreateKeyAsync(string keyName, string keyType)
    {
        using HttpResponseMessage response = await _httpClient.PostAsJsonAsync(
            $"/v1/transit/keys/{keyName}", new { type = keyType });
        await EnsureSuccessAsync(response);
    }

    /// <summary>
    /// Signs an already computed digest with a Transit key and returns the raw RSA
    /// signature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Calls <c>POST /v1/transit/sign/{keyName}</c> with:
    /// <list type="bullet">
    /// <item><c>prehashed = true</c>: the input is already a hash, so Vault signs it as it
    /// is. Without it Vault hashes the digest again and the PDF signature does not
    /// verify.</item>
    /// <item><c>signature_algorithm = pkcs1v15</c>: Vault's default for RSA keys is PSS,
    /// but the PDF signature here is <c>sha256WithRSAEncryption</c> (PKCS#1 v1.5).</item>
    /// <item><c>key_version</c>: pins the signature to the key version in the
    /// certificate.</item>
    /// <item><c>hash_algorithm</c>: Vault checks the digest length against it; a mismatch
    /// fails with 500 "crypto/rsa: input must be hashed message".</item>
    /// </list>
    /// </para>
    /// <para>
    /// Vault answers <c>vault:v{version}:{base64 signature}</c>; the method returns the
    /// decoded signature bytes (256 bytes for RSA-2048). A token without <c>update</c> on
    /// <c>transit/sign/{keyName}</c> gets 403, which throws with Vault's message.
    /// </para>
    /// </remarks>
    /// <param name="keyName">Transit key name.</param>
    /// <param name="keyVersion">Key version; the same version as in the
    /// certificate.</param>
    /// <param name="hash">The digest to sign.</param>
    /// <param name="hashAlgorithm">Vault name of the digest algorithm, e.g.
    /// "sha2-256".</param>
    /// <returns>The raw signature bytes.</returns>
    public async Task<byte[]> SignHashAsync(
        string keyName, int keyVersion, byte[] hash, string hashAlgorithm)
    {
        var request = new
        {
            input = Convert.ToBase64String(hash),
            key_version = keyVersion,
            hash_algorithm = hashAlgorithm,
            prehashed = true,
            signature_algorithm = "pkcs1v15"
        };
        using HttpResponseMessage response =
            await _httpClient.PostAsJsonAsync($"/v1/transit/sign/{keyName}", request);
        await EnsureSuccessAsync(response);

        // Vault returns "vault:v<version>:<base64 signature>".
        using JsonDocument json =
            JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        string signature = json.RootElement.GetProperty("data").GetProperty("signature")
                .GetString()
            ?? throw new InvalidOperationException("Vault returned no signature.");
        return Convert.FromBase64String(signature[(signature.LastIndexOf(':') + 1)..]);
    }

    public void Dispose() => _httpClient.Dispose();

    /// <summary>
    /// Throws with Vault's own error text when a request fails.
    /// </summary>
    private static async Task EnsureSuccessAsync(HttpResponseMessage response)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        string body = await response.Content.ReadAsStringAsync();
        string errors = body;
        try
        {
            using JsonDocument json = JsonDocument.Parse(body);
            if (json.RootElement.TryGetProperty("errors", out JsonElement list))
            {
                // Vault's messages contain line breaks and tabs: keep them on one line.
                errors = string.Join("; ", list.EnumerateArray()
                    .Select(e => Regex.Replace(e.GetString() ?? "", @"\s+", " ").Trim()));
            }
        }
        catch (JsonException)
        {
            // Not JSON: keep the raw body.
        }

        throw new HttpRequestException(
            $"Vault {response.RequestMessage?.Method} "
                + $"{response.RequestMessage?.RequestUri?.AbsolutePath} "
                + $"failed with {(int)response.StatusCode}: {errors}",
            null,
            response.StatusCode);
    }
}
