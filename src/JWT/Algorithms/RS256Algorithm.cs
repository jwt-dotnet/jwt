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
        /// Signs the provided byte array with the provided key.
        /// </summary>
        /// <param name="key">The key used to sign the data.</param>
        /// <param name="bytesToSign">The data to sign.</param>
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
#if NETSTANDARD1_3
            var rsa = (RSACryptoServiceProvider)_cert.GetRSAPrivateKey();
#else
            var rsa = (RSACryptoServiceProvider)_cert.PrivateKey;
#endif
            var param = new CspParameters
            {
                KeyContainerName = rsa.CspKeyContainerInfo.KeyContainerName,
                KeyNumber = rsa.CspKeyContainerInfo.KeyNumber == KeyNumber.Exchange ? 1 : 2
            };
            var csp = new RSACryptoServiceProvider(param) { PersistKeyInCsp = false };
            return csp.SignData(bytesToSign, "SHA256");
        }

        /// <summary>
        /// The algorithm name.
        /// </summary>
        public string Name => JwtHashAlgorithm.RS256.ToString();
    }
}