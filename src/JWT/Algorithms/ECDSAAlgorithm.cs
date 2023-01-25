#if NETSTANDARD2_0 || NET6_0_OR_GREATER
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <summary>
    /// Abstract base class for all ECDSA algorithms
    /// </summary>
    public abstract class ECDSAAlgorithm : CertificateAlgorithm<ECDsa>
    {
        /// <summary>
        /// Creates an instance of <see cref="ECDSAAlgorithm" /> using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        protected ECDSAAlgorithm(ECDsa publicKey, ECDsa privateKey)
            : base(publicKey, privateKey)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="ECDSAAlgorithm" /> using the provided public key only.
        /// </summary>
        /// <remarks>
        /// An instance created using this constructor can only be used for verifying the data, not for signing it.
        /// </remarks>
        /// <param name="publicKey">The public key for verifying the data.</param>
        protected ECDSAAlgorithm(ECDsa publicKey)
            : base(publicKey)
        {
        }

        /// <summary>
        /// Creates an instance using the provided certificate.
        /// </summary>
        /// <param name="cert">The certificate having a public key and an optional private key.</param>
        protected ECDSAAlgorithm(X509Certificate2 cert)
            : base(cert)
        {
        }

        protected override ECDsa GetPublicKey(X509Certificate2 cert) =>
            cert.GetECDsaPublicKey();

        protected override ECDsa GetPrivateKey(X509Certificate2 cert) =>
            cert.GetECDsaPrivateKey();


        protected override byte[] SignData(byte[] bytesToSign) =>
            _privateKey.SignData(bytesToSign, this.HashAlgorithmName);

        protected override bool VerifyData(byte[] bytesToSign, byte[] signature) =>
            _publicKey.VerifyData(bytesToSign, signature, this.HashAlgorithmName);
    }
}
#endif
