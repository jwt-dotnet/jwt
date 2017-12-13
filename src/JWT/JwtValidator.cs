using System;
using System.Collections.Generic;
using System.Text;

namespace JWT
{
    /// <summary>
    /// Jwt ValidTor.
    /// </summary>
    public sealed class JwtValidator : IJwtValidator
    {
        /// <summary>
        /// Describes a point in time, defined as the number of seconds that have elapsed since 00:00:00 UTC, Thursday, 1 January 1970, not counting leap seconds.
        /// See https://en.wikipedia.org/wiki/Unix_time />
        /// </summary>
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        private readonly IJsonSerializer _jsonSerializer;
        private readonly IDateTimeProvider _dateTimeProvider;

        /// <summary>
        /// Creates an instance of <see cref="JwtValidator" />.
        /// </summary>
        /// <param name="jsonSerializer">The Json Serializer.</param>
        /// <param name="dateTimeProvider">The DateTime Provider.</param>
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
            if (String.IsNullOrWhiteSpace(payloadJson))
                throw new ArgumentException(nameof(payloadJson));

            if (String.IsNullOrWhiteSpace(decodedCrypto))
                throw new ArgumentException(nameof(decodedCrypto));

            if (String.IsNullOrWhiteSpace(decodedSignature))
                throw new ArgumentException(nameof(decodedSignature));

            if (!CompareCryptoWithSignature(decodedCrypto, decodedSignature))
            {
                throw new SignatureVerificationException("Invalid signature")
                {
                    Expected = decodedCrypto,
                    Received = decodedSignature
                };
            }

            var payloadData = _jsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);

            var now = _dateTimeProvider.GetNow();
            var secondsSinceEpoch = Math.Round((now - UnixEpoch).TotalSeconds);

            ValidateExpClaim(payloadData, secondsSinceEpoch);
            ValidateNbfClaim(payloadData, secondsSinceEpoch);
        }

        /// <remarks>In the future this method can be opened for extension so made protected virtual</remarks>
        private static bool CompareCryptoWithSignature(string decodedCrypto, string decodedSignature)
        {
            if (decodedCrypto.Length != decodedSignature.Length)
            {
                return false;
            }

            byte[] decodedCryptoBytes = Encoding.ASCII.GetBytes(decodedCrypto);
            byte[] decodedSignatureBytes = Encoding.ASCII.GetBytes(decodedSignature);

            byte result = 0;
            for (int i = 0; i < decodedCrypto.Length; i++)
            {
                result |= (byte)(decodedCryptoBytes[i] ^ decodedSignatureBytes[i]);
            }

            return result == 0;
        }

        /// <summary>
        /// Verifies the 'exp' claim.
        /// </summary>
        /// <remarks>See https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4</remarks>
        /// <exception cref="SignatureVerificationException" />
        /// <exception cref="TokenExpiredException" />
        private static void ValidateExpClaim(IDictionary<string, object> payloadData, double secondsSinceEpoch)
        {
            if (!payloadData.TryGetValue("exp", out var expObj))
            {
                return;
            }

            if (expObj == null)
            {
                throw new SignatureVerificationException("Claim 'exp' must be a number.");
            }

            double expValue;
            try
            {
                expValue = Convert.ToDouble(expObj);
            }
            catch
            {
                throw new SignatureVerificationException("Claim 'exp' must be a number.");
            }

            if (secondsSinceEpoch >= expValue)
            {
                throw new TokenExpiredException("Token has expired.")
                {
                    Expiration = UnixEpoch.AddSeconds(expValue),
                    PayloadData = payloadData
                };
            }
        }

        /// <summary>
        /// Verifies the 'nbf' claim.
        /// </summary>
        /// <remarks>See https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.5</remarks>
        /// <exception cref="SignatureVerificationException" />
        private static void ValidateNbfClaim(IDictionary<string, object> payloadData, double secondsSinceEpoch)
        {
            if (!payloadData.TryGetValue("nbf", out var nbfObj))
            {
                return;
            }

            if (nbfObj == null)
            {
                throw new SignatureVerificationException("Claim 'nbf' must be a number.");
            }

            double nbfValue;
            try
            {
                nbfValue = Convert.ToDouble(nbfObj);
            }
            catch
            {
                throw new SignatureVerificationException("Claim 'nbf' must be a number.");
            }

            if (secondsSinceEpoch < nbfValue)
            {
                throw new SignatureVerificationException("Token is not yet valid.");
            }
        }
    }
}