using GroupDocs.Signature.Options;
using HashAlgorithm = GroupDocs.Signature.Domain.HashAlgorithm;

namespace VaultCustomSignHash;

/// <summary>
/// Signs the digest that GroupDocs.Signature computed, with a key that stays in HashiCorp
/// Vault Transit.
/// </summary>
public class VaultSigner : ICustomSignHash
{
    private readonly VaultTransitClient _vault;
    private readonly string _keyName;
    private readonly int _keyVersion;

    /// <summary>
    /// Creates a signer bound to one Vault Transit key version.
    /// </summary>
    /// <remarks>
    /// Pass the key version that the certificate was made for. A certificate holds one
    /// public key, so if Vault signed with another version (for example the latest one
    /// after a key rotation), the PDF would be written without any error but would not
    /// verify.
    /// </remarks>
    /// <param name="vault">Vault Transit client used for the sign requests.</param>
    /// <param name="keyName">Transit key name.</param>
    /// <param name="keyVersion">Key version in the signing certificate.</param>
    public VaultSigner(VaultTransitClient vault, string keyName, int keyVersion)
    {
        _vault = vault;
        _keyName = keyName;
        _keyVersion = keyVersion;
    }

    /// <summary>
    /// Gets the digest of the PDF signed by Vault and returns the raw signature bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Implements <see cref="ICustomSignHash"/>, the GroupDocs.Signature hook for external
    /// signing. GroupDocs.Signature calls it once per PDF signature, set through
    /// <c>DigitalSignOptions.CustomSignHash</c>. <paramref name="signableHash"/> is
    /// already a digest of the PDF's signed bytes (32 bytes for SHA-256), and it is
    /// exactly the value the signature must cover, so it goes to Vault with
    /// <c>prehashed = true</c> and is never hashed again.
    /// </para>
    /// <para>
    /// Since 26.9 <paramref name="hashAlgorithm"/> is the algorithm GroupDocs.Signature
    /// really used, never <c>Auto</c>, so it maps one to one to Vault names: Sha1 to
    /// <c>sha1</c>, Sha256 to <c>sha2-256</c>, Sha384 to <c>sha2-384</c>, Sha512 to
    /// <c>sha2-512</c>. Any other value throws <see cref="NotSupportedException"/>. SHA-1
    /// works but is a legacy algorithm that validators may reject.
    /// </para>
    /// <para>
    /// The interface is synchronous, so the method waits for the HTTP call; in a console
    /// app there is no synchronization context to deadlock on. If Vault refuses (for
    /// example 403 for a token without sign rights), the exception stops
    /// <c>Signature.Sign</c>.
    /// </para>
    /// </remarks>
    /// <param name="signableHash">The digest computed by GroupDocs.Signature.</param>
    /// <param name="hashAlgorithm">The algorithm that produced the digest.</param>
    /// <param name="signatureContext">Signing context from GroupDocs.Signature (not
    /// used).</param>
    /// <returns>The raw RSA PKCS#1 v1.5 signature over the digest.</returns>
    public byte[] CustomSignHash(
        byte[] signableHash,
        HashAlgorithm hashAlgorithm,
        SignatureContext signatureContext)
    {
        // ICustomSignHash is synchronous, so wait for the HTTP call. Safe in a console
        // app: there is no synchronization context to deadlock on.
        return _vault.SignHashAsync(
                _keyName, _keyVersion, signableHash, ToVaultHashAlgorithm(hashAlgorithm))
            .GetAwaiter().GetResult();
    }

    private static string ToVaultHashAlgorithm(HashAlgorithm hashAlgorithm) =>
        hashAlgorithm switch
        {
            HashAlgorithm.Sha1 => "sha1",
            HashAlgorithm.Sha256 => "sha2-256",
            HashAlgorithm.Sha384 => "sha2-384",
            HashAlgorithm.Sha512 => "sha2-512",
            _ => throw new NotSupportedException(
                $"Hash algorithm {hashAlgorithm} is not supported.")
        };
}
