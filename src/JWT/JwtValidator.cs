using System;
using System.Collections.Generic;
using System.Linq;
using JWT.Algorithms;
using JWT.Exceptions;

#if NET35 || NET40
using IReadOnlyPayloadDictionary = System.Collections.Generic.IDictionary<string, object>;
using TimeClaimValidationInfo = System.Func<System.Collections.Generic.IDictionary<string, object>, double, double, System.Exception>;
using StringClaimValidationInfo = System.Func<System.Collections.Generic.IDictionary<string, object>, string, System.Exception>;
#else
using IReadOnlyPayloadDictionary = System.Collections.Generic.IReadOnlyDictionary<string, object>;
using TimeClaimValidationInfo = System.Func<System.Collections.Generic.IReadOnlyDictionary<string, object>, double, double, System.Exception>;
using StringClaimValidationInfo = System.Func<System.Collections.Generic.IReadOnlyDictionary<string, object>, string, System.Exception>;
#endif
using static JWT.Internal.EncodingHelper;
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
        private readonly JwtClaimValidation _claimValidation;

        /// <summary>
        /// Creates an instance of <see cref="JwtValidator" />
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="dateTimeProvider">The DateTime Provider</param>
        public JwtValidator(IJsonSerializer jsonSerializer, IDateTimeProvider dateTimeProvider)
            : this(jsonSerializer, dateTimeProvider, new JwtClaimValidation())
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="JwtValidator" /> with time margin
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="dateTimeProvider">The DateTime Provider</param>
        /// <param name="claimValidation">information needed for validating claims</param>
        public JwtValidator(IJsonSerializer jsonSerializer, IDateTimeProvider dateTimeProvider, JwtClaimValidation claimValidation)
        {
            _jsonSerializer = jsonSerializer;
            _dateTimeProvider = dateTimeProvider;
            _claimValidation = claimValidation ?? throw new ArgumentNullException(nameof(claimValidation));
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

            //return ValidateExpClaim(payloadData, secondsSinceEpoch) ?? ValidateNbfClaim(payloadData, secondsSinceEpoch);
            return ValidateClaims(payloadData, secondsSinceEpoch);
        }

        private static bool AreAllDecodedSignaturesNullOrWhiteSpace(IEnumerable<string> decodedSignatures) =>
            decodedSignatures.All(sgn => IsNullOrWhiteSpace(sgn));

        private static bool IsAnySignatureValid(string decodedCrypto, IEnumerable<string> decodedSignatures) =>
            decodedSignatures.Any(decodedSignature => CompareCryptoWithSignature(decodedCrypto, decodedSignature));

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

        private struct ClaimInfo<T> where T : Delegate
        {
            public string name;
            public bool isExpected;
            public T validator;
        }

        /// <summary>
        /// initiate jwt claims validation.
        /// </summary>
        /// <exception cref="SignatureVerificationException" />
        /// <exception cref="TokenExpiredException" />
        private Exception ValidateClaims(IReadOnlyPayloadDictionary payloadData, double secondsSinceEpoch)
        {
            var timeClaims = new[]
            {
                new ClaimInfo<TimeClaimValidationInfo>
                {
                    name = "iat", isExpected = _claimValidation.IssuedAtMustExist,
                    validator = _claimValidation.IssuedAtValidator
                },
                new ClaimInfo<TimeClaimValidationInfo>
                {
                    name = "exp", isExpected = _claimValidation.ExpireMustExist,
                    validator = _claimValidation.ExpireValidator
                },
                new ClaimInfo<TimeClaimValidationInfo>
                {
                    name = "nbf", isExpected = _claimValidation.NotBeforeMustExist,
                    validator = _claimValidation.NotBeforeValidator
                }
            };

            foreach (var claim in timeClaims)
            {
                var ex = GetClaimValue(payloadData, claim.name, claim.isExpected, out var value);

                if (ex == null && !claim.isExpected) continue;
                if (ex != null) return ex;

                try
                {
                    var timeValue = Convert.ToDouble(value);

                    ex = claim.validator(payloadData, timeValue, secondsSinceEpoch);
                    if (ex != null) return ex;
                }
                catch
                {
                    return new SignatureVerificationException($"Claim '{claim.name}' must be a number.");
                }
            }

            var stringClaims = new[]
            {
                new ClaimInfo<StringClaimValidationInfo>
                {
                    name = "iss", isExpected = _claimValidation.IssuerMustExist,
                    validator = _claimValidation.IssuerValidator
                },
                new ClaimInfo<StringClaimValidationInfo>
                {
                    name = "sub", isExpected = _claimValidation.SubjectMustExist,
                    validator = _claimValidation.SubjectValidator
                }
            };

            foreach (var claim in stringClaims)
            {
                var ex = GetClaimValue(payloadData, claim.name, claim.isExpected, out var value);

                if (ex == null && !claim.isExpected) continue;
                if (ex != null) return ex;
                
                ex = claim.validator(payloadData, value as string);
                if (ex != null) return ex;
            }

            return null;
        }

        private Exception GetClaimValue(IReadOnlyPayloadDictionary payloadData, string claimName, bool isExpected, out object claimValue)
        {
            if (!payloadData.TryGetValue(claimName, out claimValue) && !isExpected)
                return null;

            return claimValue is null ? new SignatureVerificationException($"Claim '{claimName}' must be a number.") : null;
        }
    }
}
