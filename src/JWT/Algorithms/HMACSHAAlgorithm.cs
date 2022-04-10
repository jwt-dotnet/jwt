using System;
using System.Security.Cryptography;

namespace JWT.Algorithms
{
    [Obsolete(ObsoleteMessage, error: false)]
    public abstract class HMACSHAAlgorithm : IJwtAlgorithm
    {
        internal const string ObsoleteMessage = "HMAC SHA based algorithms are not secure to protect modern web applications. Consider switching to RSASSA or ECDSA.";

        /// <inheritdoc />
        public abstract string Name { get; }

        /// <inheritdoc />
        public abstract HashAlgorithmName HashAlgorithmName { get; }

        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using var sha = CreateAlgorithm(key);
            return sha.ComputeHash(bytesToSign);
        }

        protected abstract HMAC CreateAlgorithm(byte[] key);
    }
}