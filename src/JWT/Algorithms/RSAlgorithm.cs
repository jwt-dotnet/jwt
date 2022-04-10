using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256
    /// </summary>
    public abstract class RSAlgorithm : IAsymmetricAlgorithm
    {
        private readonly RSA _publicKey;
        private readonly RSA _privateKey;

        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithm" /> using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        protected RSAlgorithm(RSA publicKey, RSA privateKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        }

        /// <summary>
        /// Creates an instance of <see cref="RSAlgorithm" /> using the provided public key only.
        /// </summary>
        /// <remarks>
        /// An instance created using this constructor can only be used for verifying the data, not for signing it.
        /// </remarks>
        /// <param name="publicKey">The public key for verifying the data.</param>
        protected RSAlgorithm(RSA publicKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            _privateKey = null;
        }

        /// <summary>
        /// Creates an instance using the provided certificate.
        /// </summary>
        /// <param name="cert">The certificate having a public key and an optional private key.</param>
        protected RSAlgorithm(X509Certificate2 cert)
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
        public byte[] Sign(byte[] bytesToSign) =>
#if NET35 || NET40
            ((RSACryptoServiceProvider)_privateKey).SignData(bytesToSign, this.HashAlgorithmName.Name);
#else
            _privateKey.SignData(bytesToSign, this.HashAlgorithmName, RSASignaturePadding.Pkcs1);
#endif

        /// <inheritdoc />
        public bool Verify(byte[] bytesToSign, byte[] signature) =>
#if NET35 || NET40
            ((RSACryptoServiceProvider)_publicKey).VerifyData(bytesToSign, this.HashAlgorithmName.Name, signature);
#else
            _publicKey.VerifyData(bytesToSign, signature, this.HashAlgorithmName, RSASignaturePadding.Pkcs1);
#endif

        private static RSA GetPrivateKey(X509Certificate2 cert)
        {
            if (cert is null)
                throw new ArgumentNullException(nameof(cert));

#if NETSTANDARD || NETCOREAPP || NET462
            return cert.GetRSAPrivateKey();
#else
            return (RSA)cert.PrivateKey;
#endif
        }

        private static RSA GetPublicKey(X509Certificate2 cert)
        {
            if (cert is null)
                throw new ArgumentNullException(nameof(cert));

#if NETSTANDARD || NETCOREAPP || NET462
            return cert.GetRSAPublicKey();
#else
            return (RSA)cert.PublicKey.Key;
#endif
        }
    }
}