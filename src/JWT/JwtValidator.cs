using System;
using System.Collections.Generic;
using System.Linq;
using JWT.Algorithms;
using JWT.Exceptions;

#if NET35 || NET40
using IReadOnlyPayloadDictionary = System.Collections.Generic.IDictionary<string, object>;
using IReadOnlyList = System.Collections.Generic.IList<string>;
#else
using IReadOnlyPayloadDictionary = System.Collections.Generic.IReadOnlyDictionary<string, object>;
using IReadOnlyList = System.Collections.Generic.IReadOnlyList<string>;
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

        /// <summary>
        /// Creates an instance of <see cref="JwtValidator" />
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="dateTimeProvider">The DateTime Provider</param>
        public JwtValidator(IJsonSerializer jsonSerializer, IDateTimeProvider dateTimeProvider)
            : this(jsonSerializer, dateTimeProvider,
                new JwtClaimValidation{TimeMarginInSeconds = 0, Validator = ClaimValidator})
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="JwtValidator" /> with time margin
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="dateTimeProvider">The DateTime Provider</param>
        /// <param name="timeMargin">Time margin in seconds for exp and nbf validation</param>
        public JwtValidator(IJsonSerializer jsonSerializer, IDateTimeProvider dateTimeProvider, int timeMargin)
            : this(jsonSerializer, dateTimeProvider,
                new JwtClaimValidation{TimeMarginInSeconds = timeMargin, Validator = ClaimValidator})
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="JwtValidator" /> with time margin
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer</param>
        /// <param name="dateTimeProvider">The DateTime Provider</param>
        /// <param name="claimValidation">claim validation information</param>
        public JwtValidator(IJsonSerializer jsonSerializer, IDateTimeProvider dateTimeProvider, JwtClaimValidation claimValidation)
        {
            _jsonSerializer = jsonSerializer;
            _dateTimeProvider = dateTimeProvider;
            ClaimValidation = claimValidation ?? throw new ArgumentNullException(nameof(claimValidation));
        }

        /// <inheritdoc />
        public JwtClaimValidation ClaimValidation { get; }

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

            return ValidateClaims(payloadData, secondsSinceEpoch);
        }

                /// <summary>
        /// initiate jwt claims validation.
        /// </summary>
        /// <exception cref="SignatureVerificationException" />
        /// <exception cref="TokenExpiredException" />
        private Exception ValidateClaims(IReadOnlyPayloadDictionary payloadData, double secondsSinceEpoch)
        {
            if (ClaimValidation.Validator == null) return null;

            var context = new JwtClaimValidationContext{Claims = payloadData, NowInSecondsSinceEpoch = secondsSinceEpoch};

            foreach (var claim in new[] { "exp", "iat", "nbf", "iss", "sub", "aud" })
            {
                var ex = GetClaimValue(claim, out var value);

                if (ex != null) return ex;
                if (value == null) continue;

                switch (claim)
                {
                    case "exp":
                        ex = GetNumber(claim, value, out var num);
                        if (ex != null) return ex;
                        context.Expire = num;
                        break;

                    case "iat":
                        ex = GetNumber(claim, value, out num);
                        if (ex != null) return ex;
                        context.IssuedAt = num;
                        break;

                    case "nbf":
                        ex = GetNumber(claim, value, out num);
                        if (ex != null) return ex;
                        context.NotBefore = num;
                        break;

                    case "iss":
                        ex = GetString(claim, value, out var str);
                        if (ex != null) return ex;
                        context.Issuer = str;
                        break;

                    case "sub":
                        ex = GetString(claim, value, out str);
                        if (ex != null) return ex;
                        context.Subject = str;
                        break;

                    case "aud":
                        ex = GetList(claim, value, out var list);
                        if (ex != null) return ex;
                        context.Audiences = list;
                        break;
                }
            }

            return ClaimValidation.Validator(context, ClaimValidation.TimeMarginInSeconds);

            Exception GetClaimValue(string claimName, out object claimValue)
            {
                if (!payloadData.TryGetValue(claimName, out claimValue))
                    return null;

                return claimValue is null ? new SignatureVerificationException($"Claim '{claimName}' must have a value.") : null;
            }

            Exception GetNumber(string claimName, object value, out double result)
            {
                try
                {
                    result = Convert.ToDouble(value);
                    return null;
                }
                catch
                {
                    result = 0;
                    return new SignatureVerificationException($"Claim '{claimName}' must be a number.");
                }
            }

            Exception GetString(string claimName, object value, out string result)
            {
                result = value as string;

                return result == null ? new SignatureVerificationException($"Claim '{claimName}' must be a string.") : null;
            }

            Exception GetList(string claimName, object value, out IReadOnlyList result)
            {
                var str = value as string;

                if (str == null)
                {
                    result = null;
                    return new SignatureVerificationException($"Claim '{claimName}' must be a string or a string array.");
                }

                if (!str.Trim().StartsWith("["))
                {
                    result = new[] {str};
                    return null;
                }

                result = _jsonSerializer.Deserialize<List<string>>(str);
                return null;
            }
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

        private static Exception ClaimValidator(JwtClaimValidationContext context, int timeMargin)
        {
            return context.ValidateExpireClaim(timeMargin) ?? context.ValidateNotBeforeClaim(timeMargin);
        }
    }
}
