using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256
    /// </summary>
    public sealed class RS256Algorithm : IJwtAlgorithm
    {
        private readonly RSACryptoServiceProvider _publicKey;
        private readonly RSA _privateKey;

        /// <summary>
        /// Creates an instance using the provided certificate.
        /// </summary>
        /// <param name="publicKey">The RSA service provider for verifying the data.</param>
        /// <param name="privateKey">The RSA key for signing the data.</param>
        public RS256Algorithm(RSACryptoServiceProvider publicKey, RSA privateKey)
        {
            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        /// <inheritdoc />
        public string Name => JwtHashAlgorithm.RS256.ToString();

        /// <inheritdoc />
        public bool IsAsymmetric { get; } = true;

        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign) => Sign(bytesToSign);

        /// <summary>
        /// Signs the provided bytes.
        /// </summary>
        /// <param name="bytesToSign">The bytes to sign.</param>
        /// <returns>The signed bytes.</returns>
        public byte[] Sign(byte[] bytesToSign)
        {
            return _privateKey.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Verifies provided byte array with provided signature.
        /// </summary>
        /// <param name="bytesToSign">The data to verify</param>
        /// <param name="signature">The signature to verify with</param>
        public bool Verify(byte[] bytesToSign, byte[] signature)
        {
            // 2.16.840.1.101.3.4.2.1 is the object id for the sha256NoSign algorithm.
            // See https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
            // for further details.
            return _publicKey.VerifyData(bytesToSign, "2.16.840.1.101.3.4.2.1", signature);
        }
    }
}