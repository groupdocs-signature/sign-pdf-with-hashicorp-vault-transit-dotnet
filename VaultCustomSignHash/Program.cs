using System.Security.Cryptography.X509Certificates;
using GroupDocs.Signature;
using GroupDocs.Signature.Domain;
using GroupDocs.Signature.Options;

namespace VaultCustomSignHash;

internal class Program
{
    // Defaults for the local Vault from docker-compose.yml (dev mode only). Set VAULT_ADDR
    // and VAULT_TOKEN to use another Vault or a less powerful token.
    private const string DefaultVaultAddress = "http://localhost:8200";
    private const string DefaultVaultToken = "dev-only-token";
    private const string KeyName = "pdf-signing-key";

    public static async Task<int> Main()
    {
        SetLicense("REPLACE_WITH_YOUR_LICENSE_PATH");

        string inputPdf =
            Path.Combine(AppContext.BaseDirectory, "Resources", "document.pdf");
        string outputPdf = Path.Combine(AppContext.BaseDirectory, "signed_document.pdf");
        if (!File.Exists(inputPdf))
        {
            Console.WriteLine($"ERROR: input PDF not found: {inputPdf}");
            return 1;
        }

        string vaultAddress =
            Environment.GetEnvironmentVariable("VAULT_ADDR") ?? DefaultVaultAddress;
        string vaultToken =
            Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? DefaultVaultToken;

        try
        {
            Console.WriteLine($"Vault: {vaultAddress}");
            using var vault = new VaultTransitClient(vaultAddress, vaultToken);

            VaultKey key = await GetOrCreateKeyAsync(vault);
            Console.WriteLine($"Signing key: '{KeyName}', version {key.Version}");

            Console.WriteLine("Creating a self-signed certificate for the Vault key "
                + "(signed by Vault)...");
            using X509Certificate2 certificate =
                CertificateHelper.CreateSelfSignedCertificate(vault, KeyName, key);

            Console.WriteLine($"Signing '{Path.GetFileName(inputPdf)}' "
                + "(the digest goes to Vault, the key stays there)...");
            SignPdf(inputPdf, outputPdf, certificate,
                new VaultSigner(vault, KeyName, key.Version));
            Console.WriteLine($"Signed PDF: {outputPdf}");

            bool isValid = VerifyPdf(outputPdf, certificate);
            Console.WriteLine($"Signature valid: {isValid}");
            return isValid ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: {ex.Message}");
            return 1;
        }
    }

    private static void SetLicense(string licensePath)
    {
        if (File.Exists(licensePath))
        {
            new License().SetLicense(licensePath);
        }
        else
        {
            Console.WriteLine("No licence file found: running in evaluation mode "
                + "(documents of up to 2 pages).");
        }
    }

    /// <summary>
    /// Reads the signing key from Vault Transit and creates it first if it does not exist
    /// yet.
    /// </summary>
    /// <remarks>
    /// <para>
    /// No GroupDocs API here; this prepares the key that the PDF signature will use. It
    /// calls <see cref="VaultTransitClient.ReadKeyAsync"/>
    /// (<c>GET /v1/transit/keys/{name}</c>). If Vault answers 404 (no such key, or Transit
    /// not enabled), it enables Transit, creates an RSA-2048 key and reads it again. The
    /// result is the key's latest version and its public key in PEM.
    /// </para>
    /// <para>
    /// Reading first matters for least privilege: a token that may only read the key and
    /// sign with it (policy <c>vault/sample-signer.hcl</c>) skips the setup and never
    /// needs admin rights. Without such rights the setup calls fail with 403, which is the
    /// expected answer.
    /// </para>
    /// <para>
    /// In production an administrator creates the key once; the sample does it here so
    /// that the local demo works out of the box.
    /// </para>
    /// </remarks>
    /// <param name="vault">Vault Transit client with the address and token to use.</param>
    /// <returns>The latest key version and its public key.</returns>
    private static async Task<VaultKey> GetOrCreateKeyAsync(VaultTransitClient vault)
    {
        VaultKey? key = await vault.ReadKeyAsync(KeyName);
        if (key != null)
        {
            return key;
        }

        Console.WriteLine($"Key '{KeyName}' not found: enabling Transit and creating "
            + "an RSA-2048 key (one-time setup)...");
        await vault.EnableTransitAsync();
        await vault.CreateKeyAsync(KeyName, "rsa-2048");
        return await vault.ReadKeyAsync(KeyName)
            ?? throw new InvalidOperationException(
                $"Key '{KeyName}' was not found after it was created.");
    }

    /// <summary>
    /// Signs a PDF with a digital signature whose private key stays in HashiCorp Vault.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Uses <see cref="Signature.Sign(string, SignOptions)"/> with
    /// <see cref="DigitalSignOptions"/>. GroupDocs.Signature prepares the PDF, computes
    /// the SHA-256 digest of the signed byte range and calls
    /// <see cref="DigitalSignOptions.CustomSignHash"/>, here a <see cref="VaultSigner"/>
    /// that gets the digest signed by Vault. GroupDocs then embeds the signature and the
    /// certificate. Input: a PDF path; output: the signed PDF at
    /// <paramref name="outputPdf"/>.
    /// </para>
    /// <para>
    /// Notable options:
    /// <list type="bullet">
    /// <item><c>Signature = new DigitalSignature(certificate)</c>: the certificate holds
    /// only the public key, so it is passed as an object. <c>DigitalSignOptions(path)</c>
    /// expects a certificate file with a private key and fails with "Specified certificate
    /// doesn't contain private key".</item>
    /// <item><c>SignTime = DateTime.Now</c>: a local time is stored in the PDF with its
    /// time zone (for example <c>+02'00'</c>). The default UTC time is stored without one,
    /// and PDF readers then read it as their own local time.</item>
    /// <item><c>HashAlgorithm = Sha256</c>: also the default for PDF since 26.9.</item>
    /// <item><c>Visible</c> with bottom/right alignment and a margin: a 300 x 80 pt box in
    /// the bottom-right corner with signer, date, reason, location and contact.</item>
    /// </list>
    /// </para>
    /// <para>
    /// Edge cases: if signing fails (for example Vault refuses with 403), the partial
    /// output file is deleted, because a failed sign can leave a half-written PDF. Without
    /// a licence, evaluation mode refuses documents of more than 2 pages.
    /// </para>
    /// <para>
    /// Use this pattern when the signing key must stay in a key manager (Vault, an HSM, a
    /// cloud KMS) and the application may only ask for signatures.
    /// </para>
    /// </remarks>
    /// <param name="inputPdf">Path of the PDF to sign.</param>
    /// <param name="outputPdf">Path of the signed PDF to write.</param>
    /// <param name="certificate">Certificate with the Vault public key (no private
    /// key).</param>
    /// <param name="signer">The external signer that GroupDocs.Signature calls.</param>
    private static void SignPdf(
        string inputPdf,
        string outputPdf,
        X509Certificate2 certificate,
        ICustomSignHash signer)
    {
        var options = new DigitalSignOptions
        {
            // The certificate holds only the public key. Pass it as an object:
            // DigitalSignOptions(path) expects a certificate file with a private key. A
            // local signing time is stored in the PDF with its time zone (the default UTC
            // time is not).
            Signature = new DigitalSignature(certificate) { SignTime = DateTime.Now },
            CustomSignHash = signer,
            HashAlgorithm = HashAlgorithm.Sha256,
            // Visible box in the bottom-right corner of the page, wide enough for the
            // Reason line
            Visible = true,
            VerticalAlignment = VerticalAlignment.Bottom,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Padding { Bottom = 60, Right = 50 },
            Width = 300,
            Height = 80,
            Reason = "Document signed with HashiCorp Vault Transit",
            Contact = "vault-signer@example.com",
            Location = "HashiCorp Vault"
        };

        try
        {
            using var signature = new Signature(inputPdf);
            signature.Sign(outputPdf, options);
        }
        catch
        {
            // A failed sign can leave a half-written PDF behind.
            File.Delete(outputPdf);
            throw;
        }
    }

    /// <summary>
    /// Verifies the signed PDF against the certificate that was used to sign it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Uses <see cref="Signature.Verify(VerifyOptions)"/> with
    /// <see cref="DigitalVerifyOptions"/> built from the certificate (exported as DER
    /// bytes, the public part only). Input: the signed PDF path and the certificate;
    /// output: <see cref="VerificationResult.IsValid"/>.
    /// </para>
    /// <para>
    /// The check is cryptographic: it is <c>false</c> when the document was changed after
    /// signing or when the signature was made with another key, for example a different
    /// Vault key version than the one in the certificate. Pass the certificate: verifying
    /// without one does not tie the result to the expected signer.
    /// </para>
    /// <para>
    /// A self-signed certificate is enough for this check. PDF readers such as Adobe
    /// Acrobat additionally look for a trusted issuer and report the signer's identity as
    /// unknown.
    /// </para>
    /// </remarks>
    /// <param name="signedPdf">Path of the signed PDF.</param>
    /// <param name="certificate">The certificate that was used for signing.</param>
    /// <returns><c>true</c> if the signature is valid for this certificate.</returns>
    private static bool VerifyPdf(string signedPdf, X509Certificate2 certificate)
    {
        using var certificateStream =
            new MemoryStream(certificate.Export(X509ContentType.Cert));
        using var signature = new Signature(signedPdf);
        VerificationResult result =
            signature.Verify(new DigitalVerifyOptions(certificateStream));
        return result.IsValid;
    }
}
