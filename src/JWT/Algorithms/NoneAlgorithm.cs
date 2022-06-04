using System;
using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// Implements the "None" algorithm.
    /// </summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc7519#section-6">RFC-7519</see>
    public sealed class NoneAlgorithm : IJwtAlgorithm
    {
        /// <inheritdoc />
        public string Name => "none";

        /// <inheritdoc />
        public HashAlgorithmName HashAlgorithmName =>
            throw new NotSupportedException("The None algorithm doesn't have any hash algorithm.");

        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign) =>
            throw new NotSupportedException("The None algorithm doesn't support signing.");
    }
}
