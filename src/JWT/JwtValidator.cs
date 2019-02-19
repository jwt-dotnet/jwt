using System;
using System.Collections.Generic;
using System.Linq;

using static JWT.Internal.EncodingHelper;

namespace JWT
{
    /// <summary>
    /// Jwt validator.
    /// </summary>
    public sealed class JwtValidator : IJwtValidator
    {
        private readonly IJsonSerializer _jsonSerializer;
        private readonly IDateTimeProvider _dateTimeProvider;

        /// <summary>
        /// Creates an instance of <see cref="JwtValidator" />
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="dateTimeProvider">The DateTime Provider</param>
        public JwtValidator(IJsonSerializer jsonSerializer, IDateTimeProvider dateTimeProvider)
        {
            _jsonSerializer = jsonSerializer;
            _dateTimeProvider = dateTimeProvider;
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="SignatureVerificationException" />
        public void Validate(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            var ex = GetValidationException(payloadJson, decodedCrypto, decodedSignature);
            if (ex != null)
                throw ex;
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="SignatureVerificationException" />
        public void Validate(string payloadJson, string decodedCrypto, string[] decodedSignatures)
        {
            var ex = GetValidationException(payloadJson, decodedCrypto, decodedSignatures);
            if (ex != null)
                throw ex;
        }

        /// <summary>
        /// Given the JWT, verifies its signature correctness without throwing an exception but returning it instead
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="decodedCrypto">Decoded body</param>
        /// <param name="decodedSignature">Decoded signature</param>
        /// <param name="ex">Validation exception, if any</param>
        /// <returns>True if exception is JWT is valid and exception is null, otherwise false</returns>
        public bool TryValidate(string payloadJson, string decodedCrypto, string decodedSignature, out Exception ex)
        {
            ex = GetValidationException(payloadJson, decodedCrypto, decodedSignature);
            return ex is null;
        }

        /// <summary>
        /// Given the JWT, verifies its signatures correctness without throwing an exception but returning it instead
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON)</param>
        /// <param name="decodedCrypto">Decoded body</param>
        /// <param name="decodedSignature">Decoded signatures</param>
        /// <param name="ex">Validation exception, if any</param>
        /// <returns>True if exception is JWT is valid and exception is null, otherwise false</returns>
        public bool TryValidate(string payloadJson, string decodedCrypto, string[] decodedSignature, out Exception ex)
        {
            ex = GetValidationException(payloadJson, decodedCrypto, decodedSignature);
            return ex is null;
        }

        private Exception GetValidationException(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            if (String.IsNullOrWhiteSpace(payloadJson))
                return new ArgumentException(nameof(payloadJson));

            if (String.IsNullOrWhiteSpace(decodedCrypto))
                return new ArgumentException(nameof(decodedCrypto));

            if (String.IsNullOrWhiteSpace(decodedSignature))
                return new ArgumentException(nameof(decodedSignature));

            if (!CompareCryptoWithSignature(decodedCrypto, decodedSignature))
                return new SignatureVerificationException(decodedCrypto, decodedSignature);

            return GetValidationException(payloadJson);
        }

        private Exception GetValidationException(string payloadJson, string decodedCrypto, string[] decodedSignatures)
        {
            if (String.IsNullOrWhiteSpace(payloadJson))
                return new ArgumentException(nameof(payloadJson));

            if (String.IsNullOrWhiteSpace(decodedCrypto))
                return new ArgumentException(nameof(decodedCrypto));

            if (AreAllDecodedSignaturesNullOrWhiteSpace(decodedSignatures))
                return new ArgumentException(nameof(decodedSignatures));

            if (!IsAnySignatureValid(decodedCrypto, decodedSignatures))
                return new SignatureVerificationException(decodedCrypto, decodedSignatures);

            return GetValidationException(payloadJson);
        }

        private Exception GetValidationException(string payloadJson)
        {
            var payloadData = _jsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);

            var now = _dateTimeProvider.GetNow();
            var secondsSinceEpoch = UnixEpoch.GetSecondsSince(now);

            return ValidateExpClaim(payloadData, secondsSinceEpoch) ?? ValidateNbfClaim(payloadData, secondsSinceEpoch);
        }

        private static bool AreAllDecodedSignaturesNullOrWhiteSpace(IEnumerable<string> decodedSignatures) =>
            decodedSignatures.All(sgn => String.IsNullOrWhiteSpace(sgn));

        private static bool IsAnySignatureValid(string decodedCrypto, IEnumerable<string> decodedSignatures) =>
            decodedSignatures.Any(decodedSignature => CompareCryptoWithSignature(decodedCrypto, decodedSignature));

        /// <remarks>In the future this method can be opened for extension so made protected virtual</remarks>
        private static bool CompareCryptoWithSignature(string decodedCrypto, string decodedSignature)
        {
            if (decodedCrypto.Length != decodedSignature.Length)
                return false;

            var decodedCryptoBytes = GetBytes(decodedCrypto);
            var decodedSignatureBytes = GetBytes(decodedSignature);

            byte result = 0;
            for (var i = 0; i < decodedCrypto.Length; i++)
            {
                result |= (byte)(decodedCryptoBytes[i] ^ decodedSignatureBytes[i]);
            }

            return result == 0;
        }

        /// <summary>
        /// Verifies the 'exp' claim.
        /// </summary>
        /// <remarks>See https://tools.ietf.org/html/rfc7515#section-4.1.4</remarks>
        /// <exception cref="SignatureVerificationException" />
        /// <exception cref="TokenExpiredException" />
        private static Exception ValidateExpClaim(IDictionary<string, object> payloadData, double secondsSinceEpoch)
        {
            if (!payloadData.TryGetValue("exp", out var expObj))
                return null;

            if (expObj is null)
                return new SignatureVerificationException("Claim 'exp' must be a number.");

            double expValue;
            try
            {
                expValue = Convert.ToDouble(expObj);
            }
            catch
            {
                return new SignatureVerificationException("Claim 'exp' must be a number.");
            }

            if (secondsSinceEpoch >= expValue)
            {
                return new TokenExpiredException("Token has expired.")
                {
                    Expiration = UnixEpoch.Value.AddSeconds(expValue),
                    PayloadData = payloadData
                };
            }

            return null;
        }

        /// <summary>
        /// Verifies the 'nbf' claim.
        /// </summary>
        /// <remarks>See https://tools.ietf.org/html/rfc7515#section-4.1.5</remarks>
        /// <exception cref="SignatureVerificationException" />
        private static Exception ValidateNbfClaim(IReadOnlyDictionary<string, object> payloadData, double secondsSinceEpoch)
        {
            if (!payloadData.TryGetValue("nbf", out var nbfObj))
                return null;

            if (nbfObj is null)
                return new SignatureVerificationException("Claim 'nbf' must be a number.");

            double nbfValue;
            try
            {
                nbfValue = Convert.ToDouble(nbfObj);
            }
            catch
            {
                return new SignatureVerificationException("Claim 'nbf' must be a number.");
            }

            if (secondsSinceEpoch < nbfValue)
            {
                return new SignatureVerificationException("Token is not yet valid.");
            }

            return null;
        }
    }
}