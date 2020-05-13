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
        /// Given the JWT, verifies its signature correctness.
        /// </summary>
        /// <param name="decodedPayload">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="signature">Decoded body</param>
        /// <param name="decodedSignatures">The signatures to validate with</param>
        void Validate(string decodedPayload, string signature, params string[] decodedSignatures);

        /// <summary>
        /// Given the JWT, verifies its signature correctness.
        /// </summary>
        /// <remarks>
        /// Used by the asymmetric algorithms only.
        /// </remarks>
        /// <param name="decodedPayload">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="alg">The asymmetric algorithm to validate with</param>
        /// <param name="bytesToSign">The header and payload bytes to validate</param>
        /// <param name="decodedSignature">The signature to validate with</param>
        void Validate(string decodedPayload, IAsymmetricAlgorithm alg, byte[] bytesToSign, byte[] decodedSignature);

        /// <summary>
        /// Given the JWT, verifies its signature correctness without throwing an exception but returning it instead.
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="signature">Decoded body</param>
        /// <param name="decodedSignature">The signature to validate with</param>
        /// <param name="ex">The resulting validation exception, if any</param>
        /// <returns>Returns <c>true</c> if exception is JWT is valid and exception is null, otherwise false</returns>
        bool TryValidate(string payloadJson, string signature, string decodedSignature, out Exception ex);

        /// <summary>
        /// Given the JWT, verifies its signature correctness without throwing an exception but returning it instead.
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="signature">Decoded body</param>
        /// <param name="decodedSignature">The signatures to validate with</param>
        /// <param name="ex">The resulting validation exception, if any</param>
        /// <returns>Returns <c>true</c> if exception is JWT is valid and exception is null, otherwise false</returns>
        bool TryValidate(string payloadJson, string signature, string[] decodedSignature, out Exception ex);

        /// <summary>
        /// Given the JWT, verifies its signatures correctness without throwing an exception but returning it instead.
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="alg">The asymmetric algorithm to validate with</param>
        /// <param name="bytesToSign">The header and payload bytes to validate</param>
        /// <param name="decodedSignature">The decodedSignatures to validate with</param>
        /// <param name="ex">Validation exception, if any</param>
        /// <returns>True if exception is JWT is valid and exception is null, otherwise false</returns>
        bool TryValidate(string payloadJson, IAsymmetricAlgorithm alg, byte[] bytesToSign, byte[] decodedSignature, out Exception ex);
    }
}