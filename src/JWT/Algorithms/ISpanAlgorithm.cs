#if NET8_0_OR_GREATER
using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// A built-in algorithm that can sign data without allocating.
    /// </summary>
    internal interface ISpanAlgorithm : IJwtAlgorithm
    {
        /// <summary>
        /// Signs the data into <paramref name="destination" />, returning <see langword="false" /> if it's too small.
        /// </summary>
        bool TrySign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> bytesToSign, Span<byte> destination, out int bytesWritten);
    }

    /// <summary>
    /// A built-in asymmetric algorithm that can sign and verify data without allocating.
    /// </summary>
    internal interface ISpanAsymmetricAlgorithm : ISpanAlgorithm, IAsymmetricAlgorithm
    {
        bool Verify(ReadOnlySpan<byte> bytesToSign, ReadOnlySpan<byte> signature);
    }

    internal static class SpanAlgorithmExtensions
    {
        /// <summary>
        /// Large enough for HMAC, ECDSA and RSA signatures with keys up to 4096 bits.
        /// </summary>
        public const int MaxStackSignatureSize = 512;

        /// <summary>
        /// Returns the algorithm if it's built-in and can sign spans, otherwise <see langword="null" />.
        /// </summary>
        /// <remarks>
        /// Subclasses from other assemblies can override how data is signed or verified, so they keep using arrays.
        /// </remarks>
        public static ISpanAlgorithm AsSpanAlgorithm(this IJwtAlgorithm algorithm) =>
            algorithm is ISpanAlgorithm spanAlgorithm && algorithm.GetType().Assembly == typeof(ISpanAlgorithm).Assembly ?
                spanAlgorithm :
                null;

        /// <summary>
        /// Signs the data into <paramref name="buffer" />, or into a new array if the buffer is too small.
        /// </summary>
        public static ReadOnlySpan<byte> Sign(this ISpanAlgorithm algorithm, byte[] key, ReadOnlySpan<byte> bytesToSign, Span<byte> buffer) =>
            algorithm.TrySign(key, bytesToSign, buffer, out var bytesWritten) ?
                buffer.Slice(0, bytesWritten) :
                algorithm.Sign(key, bytesToSign.ToArray());
    }
}
#endif
