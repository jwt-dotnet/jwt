using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Provides IJwtAlgorithms.
    /// </summary>
    public interface IAlgorithmFactory
    {
        /// <summary>
        /// Creates an AlgorithmFactory using the provided algorithm enum.
        /// </summary>
        /// <param name="algorithm">The enum value of the algorithm</param>
        IJwtAlgorithm Create(JwtHashAlgorithm algorithm);
    }

    /// <summary>
    /// Extension methods for <seealso cref="IAlgorithmFactory" />
    ///</summary>
    public static class AlgorithmFactoryExtensions
    {
        public static IJwtAlgorithm Create(this IAlgorithmFactory factory, string algorithmName) =>
            factory.Create((JwtHashAlgorithm)Enum.Parse(typeof(JwtHashAlgorithm), algorithmName));
    }
}