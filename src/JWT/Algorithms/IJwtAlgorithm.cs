using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// Represents an algorithm to generate JWT signature.
    /// </summary>
    public interface IJwtAlgorithm
    {
        /// <summary>
        /// Signs provided byte array with provided key.
        /// </summary>
        /// <param name="key">The key used to sign the data</param>
        /// <param name="bytesToSign">The data to sign</param>
        byte[] Sign(byte[] key, byte[] bytesToSign);

        /// <summary>
        /// Gets algorithm name.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Gets name of the hashing algorithm (e.g. SHA-256/SHA-384/SHA-512).
        /// </summary>
        HashAlgorithmName HashAlgorithmName { get; }
    }

    /// <summary>
    /// Extension methods for <seealso cref="IJwtAlgorithm" />
    ///</summary>
    public static class JwtAlgorithmExtensions
    {
        /// <summary>
        /// Returns whether or not the algorithm is asymmetric.
        /// </summary>
        /// <param name="alg">The algorithm instance.</param>
        public static bool IsAsymmetric(this IJwtAlgorithm alg) =>
            alg is IAsymmetricAlgorithm;
    }
}