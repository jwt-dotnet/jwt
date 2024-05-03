using System.Security.Cryptography;

namespace JWT.Algorithms
{
    public abstract class HMACSHAAlgorithm : ISymmetricAlgorithm
    {
        protected HMACSHAAlgorithm()
        {   
        }

        protected HMACSHAAlgorithm(byte[] key) => this.Key = key;

        /// <inheritdoc />
        public abstract string Name { get; }

        /// <inheritdoc />
        public abstract HashAlgorithmName HashAlgorithmName { get; }

        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using var sha = CreateAlgorithm(key ?? this.Key);
            return sha.ComputeHash(bytesToSign);
        }

        public byte[] Key { get; }

        protected abstract HMAC CreateAlgorithm(byte[] key);
    }
}