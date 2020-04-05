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
        /// <param name="context">The captured context during validation of JWT inside <see cref="JwtDecoder"/></param>
        IJwtAlgorithm Create(JwtDecoderContext context);
    }
}