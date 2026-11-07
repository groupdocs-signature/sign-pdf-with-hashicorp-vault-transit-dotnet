using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace VaultCustomSignHash;

/// <summary>
/// Lets .NET <see cref="CertificateRequest"/> sign a certificate with a Vault Transit key.
/// Supports SHA-256 with RSA PKCS#1 v1.5, which is what <see cref="CertificateHelper"/>
/// asks for.
/// </summary>
public class VaultX509SignatureGenerator : X509SignatureGenerator
{
    // Built from the public key only: provides the public key and the algorithm
    // identifier, never signs.
    private readonly X509SignatureGenerator _rsaPublicKeyInfo;
    private readonly VaultTransitClient _vault;
    private readonly string _keyName;
    private readonly int _keyVersion;

    /// <summary>
    /// Creates a certificate signature generator for one Vault Transit key version.
    /// </summary>
    /// <remarks>
    /// <paramref name="publicKey"/> is the Vault public key imported into an RSA object
    /// without a private part. .NET's <see cref="X509SignatureGenerator.CreateForRSA"/> is
    /// used only for what does not need a private key: the public key info and the
    /// algorithm identifier. Every signature comes from Vault.
    /// </remarks>
    /// <param name="publicKey">The Vault public key of
    /// <paramref name="keyVersion"/>.</param>
    /// <param name="vault">Vault Transit client that signs.</param>
    /// <param name="keyName">Transit key name.</param>
    /// <param name="keyVersion">Key version that signs the certificate.</param>
    public VaultX509SignatureGenerator(
        RSA publicKey, VaultTransitClient vault, string keyName, int keyVersion)
    {
        _rsaPublicKeyInfo = CreateForRSA(publicKey, RSASignaturePadding.Pkcs1);
        _vault = vault;
        _keyName = keyName;
        _keyVersion = keyVersion;
    }

    /// <summary>
    /// Returns the Vault public key that the certificate will carry.
    /// </summary>
    /// <remarks>
    /// Called by <see cref="CertificateRequest"/> when it builds the certificate. The
    /// value comes from the RSA public key read from Vault, so the certificate's public
    /// key is the Vault key that signs the PDF.
    /// </remarks>
    /// <returns>The subject public key info.</returns>
    protected override PublicKey BuildPublicKey() => _rsaPublicKeyInfo.PublicKey;

    /// <summary>
    /// Returns the DER-encoded algorithm identifier sha256WithRSAEncryption for the
    /// certificate.
    /// </summary>
    /// <remarks>
    /// Called by <see cref="CertificateRequest"/> with the hash algorithm of the request.
    /// Only SHA-256 is supported, because <see cref="SignData"/> hashes with SHA-256 and
    /// the identifier must describe the signature that Vault really makes; any other
    /// algorithm throws <see cref="NotSupportedException"/>.
    /// </remarks>
    /// <param name="hashAlgorithm">Hash algorithm requested by the certificate
    /// request.</param>
    /// <returns>The DER-encoded AlgorithmIdentifier.</returns>
    public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
    {
        EnsureSha256(hashAlgorithm);
        return _rsaPublicKeyInfo.GetSignatureAlgorithmIdentifier(hashAlgorithm);
    }

    /// <summary>
    /// Signs the certificate data with the Vault key: hashes it here and sends only the
    /// digest.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Called by <see cref="CertificateRequest"/> with the to-be-signed certificate bytes.
    /// The method computes their SHA-256 digest and calls
    /// <see cref="VaultTransitClient.SignHashAsync"/> (<c>prehashed</c>, PKCS#1 v1.5,
    /// pinned key version). This is the first of two Vault sign requests per run; the
    /// second one signs the PDF digest.
    /// </para>
    /// <para>
    /// The method is synchronous by contract, so it waits for the HTTP call (safe in a
    /// console app). Hash algorithms other than SHA-256 throw
    /// <see cref="NotSupportedException"/>.
    /// </para>
    /// </remarks>
    /// <param name="data">The certificate data to sign.</param>
    /// <param name="hashAlgorithm">Hash algorithm requested by the certificate
    /// request.</param>
    /// <returns>The raw RSA signature from Vault.</returns>
    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        EnsureSha256(hashAlgorithm);
        byte[] hash = SHA256.HashData(data);

        // SignData is synchronous; see VaultSigner for why waiting is safe here.
        return _vault.SignHashAsync(_keyName, _keyVersion, hash, "sha2-256")
            .GetAwaiter().GetResult();
    }

    private static void EnsureSha256(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm != HashAlgorithmName.SHA256)
        {
            throw new NotSupportedException(
                "Only SHA-256 is supported for the certificate signature, "
                + $"not {hashAlgorithm.Name}.");
        }
    }
}
