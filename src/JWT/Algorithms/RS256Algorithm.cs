using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256
    /// </summary>
    public sealed class RS256Algorithm : IJwtAlgorithm
    {
        private readonly X509Certificate2 _cert;

        /// <summary>
        /// Creates an instance using the provided certificate.
        /// </summary>
        /// <param name="cert"></param>
        public RS256Algorithm(X509Certificate2 cert)
        {
            _cert = cert;
        }

        /// <inheritdoc />
        public string Name => JwtHashAlgorithm.RS256.ToString();

        /// <inheritdoc />
        public bool IsAsymmetric { get; } = true;

        /// <inheritdoc />
        public byte[] Sign(byte[] _, byte[] bytesToSign)
        {
            if (!_cert.HasPrivateKey)
                throw new CryptographicException("Certificate doesn't contain private key");

            var privateKey = GetPrivateKey(_cert);
            return privateKey.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Verifies provided byte array with provided signature.
        /// </summary>
        /// <param name="bytesToSign">The data to verify.</param>
        /// <param name="signature">The signature to verify with</param>
        /// <returns></returns>
        public bool Verify(byte[] bytesToSign, byte[] signature)
        {
            var publicKey = GetPublicKey(_cert);
            return publicKey.VerifyData(bytesToSign, "2.16.840.1.101.3.4.2.1", signature);
        }

        private static RSA GetPrivateKey(X509Certificate2 cert)
        {
#if NETSTANDARD1_3
            return cert.GetRSAPrivateKey();
#else
            return (RSA)cert.PrivateKey;
#endif
        }

        private static RSACryptoServiceProvider GetPublicKey(X509Certificate2 cert)
        {
            AsymmetricAlgorithm alg;
#if NETSTANDARD1_3
            alg = cert.GetRSAPublicKey();
#else
            alg = cert.PublicKey.Key;
#endif
            return (RSACryptoServiceProvider)alg;
        }
    }
}