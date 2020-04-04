using System;
using JWT.Algorithms;

namespace JWT
{
    /// <summary>
    /// Represents a JWT validator.
    /// </summary>
    public interface IJwtValidator
    {
        /// <summary>
        /// Given the JWT, verifies its signatures correctness.
        /// </summary>
        /// <param name="decodedPayload">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="decodedCrypto">Decoded body</param>
        /// <param name="decodedSignatures">Decoded signatures</param>
        /// <exception cref="SignatureVerificationException">The decodedSignatures is invalid</exception>
        /// <exception cref="TokenExpiredException">The token has expired</exception>
        void Validate(string decodedPayload, string decodedCrypto, params string[] decodedSignatures);

        /// <summary>
        /// Given the JWT, verifies its signatures correctness.
        /// </summary>
        /// <remarks>
        /// Used by the asymmetric algorithms only.
        /// </remarks>
        /// <param name="decodedPayload">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="alg">The asymmetric algorithm to validate with</param>
        /// <param name="bytesToSign">The header and payload bytes to validate</param>
        /// <param name="decodedSignature">The decodedSignatures to validate with</param>
        /// <exception cref="SignatureVerificationException">The decodedSignatures is invalid</exception>
        /// <exception cref="TokenExpiredException">The token has expired</exception>
        void Validate(string decodedPayload, IAsymmetricAlgorithm alg, byte[] bytesToSign, byte[] decodedSignature);

        /// <summary>
        /// Given the JWT, verifies its signature correctness without throwing an exception but returning it instead.
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="decodedCrypto">Decoded body</param>
        /// <param name="decodedSignature">Decoded signature</param>
        /// <param name="ex">Validation exception, if any</param>
        /// <returns>True if exception is JWT is valid and exception is null, otherwise false</returns>
        bool TryValidate(string payloadJson, string decodedCrypto, string decodedSignature, out Exception ex);

        /// <summary>
        /// Given the JWT, verifies its signatures correctness without throwing an exception but returning it instead.
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="decodedCrypto">Decoded body</param>
        /// <param name="decodedSignature">Decoded signatures</param>
        /// <param name="ex">Validation exception, if any</param>
        /// <returns>True if exception is JWT is valid and exception is null, otherwise false</returns>
        bool TryValidate(string payloadJson, string decodedCrypto, string[] decodedSignature, out Exception ex);
    }
}