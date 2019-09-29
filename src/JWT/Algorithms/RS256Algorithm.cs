﻿using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JWT.Algorithms
{
    /// <summary>
    /// RSASSA-PKCS1-v1_5 using SHA-256
    /// </summary>
    public sealed class RS256Algorithm : IJwtAlgorithm
    {
        /// <remarks>
        /// See https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
        /// </remarks>
        private static readonly HashAlgorithmName SHA256NoSign = new HashAlgorithmName("sha256NoSign");

        private readonly RSA _publicKey;
        private readonly RSA _privateKey;

        /// <summary>
        /// Creates an instance using the provided pair of public and private keys.
        /// </summary>
        /// <param name="publicKey">The public key for verifying the data.</param>
        /// <param name="privateKey">The private key for signing the data.</param>
        public RS256Algorithm(RSA publicKey, RSA privateKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            _privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
        }

        /// <summary>
        /// Creates an instance using the provided pair of public and private keys.
        /// </summary>
        /// <remarks>
        /// An instance created using this constructor can only be used for verifying the data, not for signing it.
        /// </remarks>
        /// <param name="publicKey">The public key for verifying the data.</param>
        public RS256Algorithm(RSA publicKey)
        {
            _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        /// <summary>
        /// Creates an instance using the provided certificate.
        /// </summary>
        /// <param name="cert">The certificate having both public and private keys.</param>
        public RS256Algorithm(X509Certificate2 cert)
            : this(GetPublicKey(cert), GetPrivateKey(cert))
        {
        }

        /// <inheritdoc />
        public string Name => JwtHashAlgorithm.RS256.ToString();

        /// <inheritdoc />
        public bool IsAsymmetric => true;

        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign) =>
            Sign(bytesToSign);

        /// <summary>
        /// Signs the provided bytes.
        /// </summary>
        /// <param name="bytesToSign">The bytes to sign.</param>
        /// <returns>The signed bytes.</returns>
        public byte[] Sign(byte[] bytesToSign) =>
            _privateKey.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        /// <summary>
        /// Verifies provided byte array with provided signature.
        /// </summary>
        /// <param name="bytesToSign">The data to verify</param>
        /// <param name="signature">The signature to verify with</param>
        public bool Verify(byte[] bytesToSign, byte[] signature)
        {
            switch (_publicKey)
            {
                 case RSACryptoServiceProvider csp:
                     return csp.VerifyData(bytesToSign, "2.16.840.1.101.3.4.2.1", signature);
                 default:
                     return _publicKey.VerifyData(bytesToSign, signature, SHA256NoSign, RSASignaturePadding.Pkcs1);
            }
        }

        private static RSA GetPrivateKey(X509Certificate2 cert)
        {
#if NETSTANDARD1_3
            return cert.GetRSAPrivateKey();
#else
            return (RSA)cert.PrivateKey;
#endif
        }

        private static RSA GetPublicKey(X509Certificate2 cert)
        {
#if NETSTANDARD1_3
            return cert.GetRSAPublicKey();
#else
            return (RSA)cert.PublicKey.Key;
#endif
        }
    }
}
