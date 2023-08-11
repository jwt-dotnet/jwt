using System.Security.Cryptography;

namespace JWT.Algorithms
{
    public abstract class HMACSHAAlgorithm : IJwtAlgorithm
    {
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