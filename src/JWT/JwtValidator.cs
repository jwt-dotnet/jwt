using System;
using System.Collections.Generic;
using JWT.Algorithms;
using JWT.Exceptions;

using static JWT.Internal.EncodingHelper;

#if NET35 || NET40
using IReadOnlyPayloadDictionary = System.Collections.Generic.IDictionary<string, object>;
#else
using IReadOnlyPayloadDictionary = System.Collections.Generic.IReadOnlyDictionary<string, object>;
#endif

#if NET35
using static JWT.Compatibility.String;
#else
using static System.String;
#endif

namespace JWT
{
    /// <summary>
    /// Jwt validator.
    /// </summary>
    public sealed class JwtValidator : IJwtValidator
    {
        private readonly IJsonSerializer _jsonSerializer;
        private readonly IDateTimeProvider _dateTimeProvider;
        private readonly int _timeMargin;

        /// <summary>
        /// Creates an instance of <see cref="JwtValidator" />
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="dateTimeProvider">The DateTime Provider</param>
        public JwtValidator(IJsonSerializer jsonSerializer, IDateTimeProvider dateTimeProvider)
            : this(jsonSerializer, dateTimeProvider, 0)
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="JwtValidator" /> with time margin
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="dateTimeProvider">The DateTime Provider</param>
        /// <param name="timeMargin">Time margin in seconds for exp and nbf validation</param>
        public JwtValidator(IJsonSerializer jsonSerializer, IDateTimeProvider dateTimeProvider, int timeMargin)
        {
            _jsonSerializer = jsonSerializer;
            _dateTimeProvider = dateTimeProvider;
            _timeMargin = timeMargin;
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="SignatureVerificationException" />
        public void Validate(string decodedPayload, string signature, params string[] decodedSignatures)
        {
            var ex = GetValidationException(decodedPayload, signature, decodedSignatures);
            if (ex is object)
                throw ex;
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        /// <exception cref="SignatureVerificationException" />
        public void Validate(string decodedPayload, IAsymmetricAlgorithm alg, byte[] bytesToSign, byte[] decodedSignature)
        {
            var ex = GetValidationException(alg, decodedPayload, bytesToSign, decodedSignature);
            if (ex is object)
                throw ex;
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        public bool TryValidate(string payloadJson, string signature, string decodedSignature, out Exception ex)
        {
            ex = GetValidationException(payloadJson, signature, decodedSignature);
            return ex is null;
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        public bool TryValidate(string payloadJson, string signature, string[] decodedSignature, out Exception ex)
        {
            ex = GetValidationException(payloadJson, signature, decodedSignature);
            return ex is null;
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentException" />
        public bool TryValidate(string payloadJson, IAsymmetricAlgorithm alg, byte[] bytesToSign, byte[] decodedSignature, out Exception ex)
        {
            ex = GetValidationException(alg, payloadJson, bytesToSign, decodedSignature);
            return ex is null;
        }

        private Exception GetValidationException(string payloadJson, string decodedCrypto, params string[] decodedSignatures)
        {
            if (AreAllDecodedSignaturesNullOrWhiteSpace(decodedSignatures))
                return new ArgumentException(nameof(decodedSignatures));

            if (!IsAnySignatureValid(decodedCrypto, decodedSignatures))
                return new SignatureVerificationException(decodedCrypto, decodedSignatures);

            return GetValidationException(payloadJson);
        }

        private Exception GetValidationException(IAsymmetricAlgorithm alg, string payloadJson, byte[] bytesToSign, byte[] decodedSignature)
        {
            if (!alg.Verify(bytesToSign, decodedSignature))
                return new SignatureVerificationException("The signature is invalid according to the validation procedure.");

            return GetValidationException(payloadJson);
        }

        private Exception GetValidationException(string payloadJson)
        {
            if (String.IsNullOrEmpty(payloadJson))
                throw new ArgumentException(nameof(payloadJson));

            var payloadData = _jsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);

            var now = _dateTimeProvider.GetNow();
            var secondsSinceEpoch = UnixEpoch.GetSecondsSince(now);

            return ValidateExpClaim(payloadData, secondsSinceEpoch) ?? ValidateNbfClaim(payloadData, secondsSinceEpoch);
        }

        private static bool AreAllDecodedSignaturesNullOrWhiteSpace(string[] decodedSignatures) =>
            Array.TrueForAll(decodedSignatures, sgn => IsNullOrWhiteSpace(sgn));

        private static bool IsAnySignatureValid(string decodedCrypto, string[] decodedSignatures) =>
            Array.Exists(decodedSignatures, decodedSignature => CompareCryptoWithSignature(decodedCrypto, decodedSignature));

        /// <remarks>In the future this method can be opened for extension hence made protected virtual</remarks>
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
        private Exception ValidateExpClaim(IReadOnlyPayloadDictionary payloadData, double secondsSinceEpoch)
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

            if (secondsSinceEpoch - _timeMargin >= expValue)
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
        private Exception ValidateNbfClaim(IReadOnlyPayloadDictionary payloadData, double secondsSinceEpoch)
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

            if (secondsSinceEpoch + _timeMargin < nbfValue)
            {
                return new SignatureVerificationException("Token is not yet valid.");
            }

            return null;
        }
    }
}