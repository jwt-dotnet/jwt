#if NETSTANDARD2_0 || NET5_0
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <summary>
    /// ECDSA using SHA-256 hash algorithm
    /// </summary>
    public sealed class ES256Algorithm : ECDSAAlgorithm
    {
        /// <summary>
        /// Creates an instance of <see cref="ES256Algorithm" /> using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        public ES256Algorithm(ECDsa publicKey, ECDsa privateKey)
            : base(publicKey, privateKey)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="ES256Algorithm" /> using the provided public key only.
        /// </summary>
        /// <remarks>
        /// An instance created using this constructor can only be used for verifying the data, not for signing it.
        /// </remarks>
        /// <param name="publicKey">The public key for verifying the data.</param>
        public ES256Algorithm(ECDsa publicKey)
            : base(publicKey)
        {
        }

        /// <summary>
        /// Creates an instance using the provided certificate.
        /// </summary>
        /// <param name="cert">The certificate having a public key and an optional private key.</param>
        public ES256Algorithm(X509Certificate2 cert)
            : base(cert)
        {
        }

        /// <inheritdoc />
        public override string Name => nameof(JwtAlgorithmName.ES256);

        // <inheritdoc />
        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;
    }
}
#endif
