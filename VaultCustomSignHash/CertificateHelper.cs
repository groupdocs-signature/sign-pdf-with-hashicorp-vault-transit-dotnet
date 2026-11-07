using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VaultCustomSignHash;

/// <summary>
/// Builds a self-signed certificate for a Vault Transit key. The certificate carries the
/// Vault public key and is signed by Vault, so no private key exists outside Vault.
/// </summary>
/// <remarks>
/// Good for a demo: PDF readers show the signature as intact but the signer as unknown. In
/// production use a certificate issued by a CA for the same key (see README).
/// </remarks>
public static class CertificateHelper
{
    /// <summary>
    /// Creates a self-signed X.509 certificate for the given Vault key version, signed by
    /// Vault.
    /// </summary>
    /// <remarks>
    /// <para>
    /// No GroupDocs API here; the result is the certificate that
    /// <c>new DigitalSignature(certificate)</c> puts into the PDF. A PDF reader checks the
    /// signature with the public key from this certificate, so it must be the Vault public
    /// key of the same version that signs.
    /// </para>
    /// <para>
    /// Uses .NET <see cref="CertificateRequest"/> with
    /// <see cref="VaultX509SignatureGenerator"/>: the certificate data is hashed locally
    /// (SHA-256) and the digest is signed through <c>transit/sign</c>. Subject and issuer
    /// are <c>CN=Vault Transit Signer</c>; key usage is digital signature; the certificate
    /// has no private key.
    /// </para>
    /// <para>
    /// It is valid from one day before now for one year. A PDF reader compares the signing
    /// time with the start date; a certificate made a second before signing was reported
    /// by Adobe Acrobat as "expired or not yet valid" on a machine two hours east of UTC.
    /// </para>
    /// <para>
    /// In production replace it with a CA-issued certificate for the same key: Transit can
    /// sign a CSR (<c>transit/keys/{name}/csr</c>), or the Vault PKI engine can act as a
    /// CA.
    /// </para>
    /// </remarks>
    /// <param name="vault">Vault Transit client that signs the certificate.</param>
    /// <param name="keyName">Transit key name.</param>
    /// <param name="key">Key version and public key read from Vault.</param>
    /// <returns>The certificate, public key only.</returns>
    public static X509Certificate2 CreateSelfSignedCertificate(
        VaultTransitClient vault, string keyName, VaultKey key)
    {
        using RSA publicKey = RSA.Create();
        publicKey.ImportFromPem(key.PublicKeyPem);

        var subject = new X500DistinguishedName("CN=Vault Transit Signer");
        var request = new CertificateRequest(
            subject, publicKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

        var generator =
            new VaultX509SignatureGenerator(publicKey, vault, keyName, key.Version);

        // Valid from yesterday: a PDF reader compares the signing time with this date, and
        // a clock or time-zone difference must not make a certificate made a second ago
        // look "not yet valid".
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return request.Create(
            subject,
            generator,
            now.AddDays(-1),
            now.AddYears(1),
            RandomNumberGenerator.GetBytes(16));
    }
}
