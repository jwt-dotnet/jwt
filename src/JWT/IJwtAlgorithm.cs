namespace JWT
{
    /// <summary>
    /// JwtAlgorithm interface.
    /// </summary>
    public interface IJwtAlgorithm
    {
        /// <summary>
        /// Signs the provided byte array with the provided key.
        /// </summary>
        /// <param name="key">The key used to sign the data.</param>
        /// <param name="bytesToSign">The data to sign.</param>
        byte[] Sign(byte[] key, byte[] bytesToSign);

        /// <summary>
        /// The algorithm name.
        /// </summary>
        string Name { get; }
    }
}