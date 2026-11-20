using System;
using System.Security.Cryptography;

namespace JWT.Algorithms
{
    public abstract class HMACSHAAlgorithm : IJwtAlgorithm
#if NET8_0_OR_GREATER
        , ISpanAlgorithm
#endif
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

#if NET8_0_OR_GREATER
        bool ISpanAlgorithm.TrySign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> bytesToSign, Span<byte> destination, out int bytesWritten) =>
            this switch
            {
                HMACSHA256Algorithm => HMACSHA256.TryHashData(key, bytesToSign, destination, out bytesWritten),
                HMACSHA384Algorithm => HMACSHA384.TryHashData(key, bytesToSign, destination, out bytesWritten),
                HMACSHA512Algorithm => HMACSHA512.TryHashData(key, bytesToSign, destination, out bytesWritten),
                _ => throw new NotSupportedException($"Algorithm {this.Name} can't sign spans.")
            };
#endif
    }
}