namespace JWT.Algorithms
{
    /// <summary>
    /// Extension methods for <seealso cref="IJwtAlgorithm" />
    ///</summary>
    public static class JwtAlgorithmExtensions
    {
        public static bool IsAsymmetric(this IJwtAlgorithm alg) =>
            alg is IAsymmetricAlgorithm;
    }
}