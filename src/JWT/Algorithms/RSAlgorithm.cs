using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256
    /// </summary>
    public abstract class RSAlgorithm : CertificateAlgorithm<RSA>
    {
        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithm" /> using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        protected RSAlgorithm(RSA publicKey, RSA privateKey)
            : base(publicKey, privateKey)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithm" /> using the provided public key only.
        /// </summary>
        /// <remarks>
        /// An instance created using this constructor can only be used for verifying the data, not for signing it.
        /// </remarks>
        /// <param name="publicKey">The public key for verifying the data.</param>
        protected RSAlgorithm(RSA publicKey)
            : base(publicKey)
        {
        }

        /// <summary>
        /// Creates an instance using the provided certificate.
        /// </summary>
        /// <param name="cert">The certificate having a public key and an optional private key.</param>
        protected RSAlgorithm(X509Certificate2 cert)
            : base(cert)
        {
        }

        protected override RSA GetPublicKey(X509Certificate2 cert) =>
#if NETSTANDARD || NETCOREAPP || NET462
            cert.GetRSAPublicKey();
#else
            (RSA)cert.PublicKey.Key;
#endif

        protected override RSA GetPrivateKey(X509Certificate2 cert) =>
#if NETSTANDARD || NETCOREAPP || NET462
            cert.GetRSAPrivateKey();
#else
            (RSA)cert.PrivateKey;
#endif

        protected override byte[] SignData(byte[] bytesToSign) =>
#if NET35 || NET40
            ((RSACryptoServiceProvider)_privateKey).SignData(bytesToSign, this.HashAlgorithmName.Name);
#else
            _privateKey.SignData(bytesToSign, this.HashAlgorithmName, RSASignaturePadding.Pkcs1);
#endif

        protected override bool VerifyData(byte[] bytesToSign, byte[] signature) =>
#if NET35 || NET40
            ((RSACryptoServiceProvider)_publicKey).VerifyData(bytesToSign, this.HashAlgorithmName.Name, signature);
#else
            _publicKey.VerifyData(bytesToSign, signature, this.HashAlgorithmName, RSASignaturePadding.Pkcs1);
#endif
    }
}
