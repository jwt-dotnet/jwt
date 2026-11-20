#if NETSTANDARD2_0 || NET6_0_OR_GREATER
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <summary>
    /// Abstract base class for all ECDSA algorithms
    /// </summary>
    public abstract class ECDSAAlgorithm : CertificateAlgorithm<ECDsa>
#if NET8_0_OR_GREATER
        , ISpanAsymmetricAlgorithm
#endif
    {
        /// <summary>
        /// Creates an instance of <see cref="ECDSAAlgorithm" /> using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        /// <exception cref="ArgumentException">A key does not have the size required by the algorithm.</exception>
        protected ECDSAAlgorithm(ECDsa publicKey, ECDsa privateKey)
            : base(publicKey, privateKey)
        {
            EnsureKeySize(publicKey, nameof(publicKey));
            EnsureKeySize(privateKey, nameof(privateKey));
        }

        /// <summary>
        /// Creates an instance of <see cref="ECDSAAlgorithm" /> using the provided public key only.
        /// </summary>
        /// <remarks>
        /// An instance created using this constructor can only be used for verifying the data, not for signing it.
        /// </remarks>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <exception cref="ArgumentException">The key does not have the size required by the algorithm.</exception>
        protected ECDSAAlgorithm(ECDsa publicKey)
            : base(publicKey)
        {
            EnsureKeySize(publicKey, nameof(publicKey));
        }

        /// <summary>
        /// Creates an instance using the provided certificate.
        /// </summary>
        /// <param name="cert">The certificate having a public key and an optional private key.</param>
        /// <exception cref="ArgumentException">The certificate's public key does not have the size required by the algorithm.</exception>
        protected ECDSAAlgorithm(X509Certificate2 cert)
            : base(cert)
        {
            EnsureKeySize(_publicKey, nameof(cert));
        }

        /// <summary>
        /// The key size, in bits, of the curve required by the algorithm (RFC 7518, section 3.4).
        /// </summary>
        protected abstract int RequiredKeySize { get; }

        protected override ECDsa GetPublicKey(X509Certificate2 cert) =>
            cert.GetECDsaPublicKey();

        protected override ECDsa GetPrivateKey(X509Certificate2 cert) =>
            cert.GetECDsaPrivateKey();


        protected override byte[] SignData(byte[] bytesToSign) =>
            _privateKey.SignData(bytesToSign, this.HashAlgorithmName);

        protected override bool VerifyData(byte[] bytesToSign, byte[] signature) =>
            _publicKey.VerifyData(bytesToSign, signature, this.HashAlgorithmName);

#if NET8_0_OR_GREATER
        bool ISpanAlgorithm.TrySign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> bytesToSign, Span<byte> destination, out int bytesWritten) =>
            GetPrivateKeyForSigning().TrySignData(bytesToSign, destination, this.HashAlgorithmName, out bytesWritten);

        bool ISpanAsymmetricAlgorithm.Verify(ReadOnlySpan<byte> bytesToSign, ReadOnlySpan<byte> signature) =>
            _publicKey.VerifyData(bytesToSign, signature, this.HashAlgorithmName);
#endif

        private void EnsureKeySize(ECDsa key, string paramName)
        {
            if (key.KeySize != this.RequiredKeySize)
            {
                throw new ArgumentException($"Algorithm {this.Name} requires a key of size {this.RequiredKeySize} bits but the provided key has size {key.KeySize} bits.", paramName);
            }
        }
    }
}
#endif
