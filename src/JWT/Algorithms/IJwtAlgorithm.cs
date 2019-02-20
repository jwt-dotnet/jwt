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
        /// Indicates whether algorithm is asymmetric or not.
        /// </summary>
        bool IsAsymmetric { get; }
    }
}