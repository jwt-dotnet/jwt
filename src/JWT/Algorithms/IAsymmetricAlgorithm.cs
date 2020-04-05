namespace JWT.Algorithms
{
    /// <summary>
    /// Represents an asymmetric algorithm to generate or validate JWT signature.
    /// </summary>
    public interface IAsymmetricAlgorithm : IJwtAlgorithm
    {
        /// <summary>
        /// Verifies provided byte array with provided signature.
        /// </summary>
        /// <param name="bytesToSign">The data to verify</param>
        /// <param name="signature">The signature to verify with</param>
        bool Verify(byte[] bytesToSign, byte[] signature);
    }
}