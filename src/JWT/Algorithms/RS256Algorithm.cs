using System;
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

        /// <summary>
        /// The algorithm name.
        /// </summary>
        public string Name => JwtHashAlgorithm.RS256.ToString();

        /// <summary>
        /// Signs the provided byte array with the provided key.
        /// </summary>
        /// <param name="key">The key used to sign the data.</param>
        /// <param name="bytesToSign">The data to sign.</param>
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            var rsa = GetRSA(_cert) ?? throw new CryptographicException("Certificate doesn't contain private key");
            return rsa.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        private static RSA GetRSA(X509Certificate2 cert)
        {
#if NETSTANDARD1_3
            return cert.GetRSAPrivateKey();
#else
            return (RSA)cert.PrivateKey;
#endif
        }
    }
}