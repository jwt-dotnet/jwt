#if NETSTANDARD2_0 || NET5_0
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <summary>
    /// Abstract base class for all ECDSA algorithms
    /// </summary>
    public abstract class ECDSAAlgorithm : IAsymmetricAlgorithm
    {
        private readonly ECDsa _publicKey;
        private readonly ECDsa _privateKey;

        /// <summary>
        /// Creates an instance of <see cref="ECDSAAlgorithm" /> using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        protected ECDSAAlgorithm(ECDsa publicKey, ECDsa privateKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        }

        /// <summary>
        /// Creates an instance of <see cref="ECDSAAlgorithm" /> using the provided public key only.
        /// </summary>
        /// <remarks>
        /// An instance created using this constructor can only be used for verifying the data, not for signing it.
        /// </remarks>
        /// <param name="publicKey">The public key for verifying the data.</param>
        protected ECDSAAlgorithm(ECDsa publicKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            _privateKey = null;
        }

        /// <summary>
        /// Creates an instance using the provided certificate.
        /// </summary>
        /// <param name="cert">The certificate having a public key and an optional private key.</param>
        protected ECDSAAlgorithm(X509Certificate2 cert)
        {
            _publicKey = GetPublicKey(cert) ?? throw new Exception("Certificate's PublicKey cannot be null.");
            _privateKey = GetPrivateKey(cert);
        }

        /// <inheritdoc />
        public abstract string Name { get; }

        /// <inheritdoc />
        public abstract HashAlgorithmName HashAlgorithmName { get; }

        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            if (_privateKey is null)
                throw new InvalidOperationException("Can't sign data without private key");

            return Sign(bytesToSign);
        }

        /// <summary>
        /// Signs the provided bytes.
        /// </summary>
        /// <param name="bytesToSign">The bytes to sign.</param>
        /// <returns>The signed bytes.</returns>
        public byte[] Sign(byte[] bytesToSign)
            => _privateKey.SignData(bytesToSign, this.HashAlgorithmName);

        /// <inheritdoc />
        public bool Verify(byte[] bytesToSign, byte[] signature)
            => _publicKey.VerifyData(bytesToSign, signature, this.HashAlgorithmName);

        private static ECDsa GetPrivateKey(X509Certificate2 cert)
        {
            if (cert is null)
                throw new ArgumentNullException(nameof(cert));

            return cert.GetECDsaPrivateKey();
        }

        private static ECDsa GetPublicKey(X509Certificate2 cert)
        {
            if (cert is null)
                throw new ArgumentNullException(nameof(cert));

            return cert.GetECDsaPublicKey();
        }
    }
}
#endif
