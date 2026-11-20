using System;
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

#if NET8_0_OR_GREATER
        /// <summary>
        /// Same as <see cref="Sign" /> without arrays.
        /// </summary>
        /// <remarks>
        /// Each built-in algorithm overrides it. It's virtual rather than abstract so that classes deriving from this one
        /// in other assemblies keep working: they can't override it, so they keep using <see cref="CreateAlgorithm" />.
        /// </remarks>
        /// <returns><see langword="false" /> if the algorithm can't sign spans or <paramref name="destination" /> is too small.</returns>
        internal virtual bool TrySign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> bytesToSign, Span<byte> destination, out int bytesWritten)
        {
            bytesWritten = 0;
            return false;
        }
#endif
    }
}