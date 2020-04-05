using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Extension methods for <seealso cref="IAlgorithmFactory" />
    ///</summary>
    public static class AlgorithmFactoryExtensions
    {
        public static IJwtAlgorithm Create(this IAlgorithmFactory factory, string algorithmName) =>
            factory.Create((JwtHashAlgorithm)Enum.Parse(typeof(JwtHashAlgorithm), algorithmName));
    }
}