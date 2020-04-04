namespace JWT.Algorithms
{
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