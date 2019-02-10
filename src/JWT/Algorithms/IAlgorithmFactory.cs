namespace JWT.Algorithms
{
    /// <summary>
    /// Provides IJwtAlgorithms.
    /// </summary>
    public interface IAlgorithmFactory
    {
        /// <summary>
        /// Creates an AlgorithmFactory using the provided algorithm name.
        /// </summary>
        /// <param name="algorithmName">The name of the algorithm</param>
        IJwtAlgorithm Create(string algorithmName);

        /// <summary>
        /// Creates an AlgorithmFactory using the provided algorithm enum.
        /// </summary>
        /// <param name="algorithm">The enum value of the algorithm</param>
        IJwtAlgorithm Create(JwtHashAlgorithm algorithm);
    }
}