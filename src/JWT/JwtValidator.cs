using System;
using System.Collections.Generic;
using System.Text;

namespace JWT
{
    public sealed class JwtValidator : IJwtValidator
    {
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        private readonly IJsonSerializer _jsonSerializer;
        private readonly IDateTimeProvider _dateTimeProvider;

        public JwtValidator(IJsonSerializer jsonSerializer, IDateTimeProvider dateTimeProvider)
        {
            _jsonSerializer = jsonSerializer;
            _dateTimeProvider = dateTimeProvider;
        }

        /// <inheritdoc />
        public void Validate(string payloadJson, string decodedCrypto, string decodedSignature)
        {
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

            // verify exp claim https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4
            object expObj;
            if (payloadData.TryGetValue("exp", out expObj))
            {
                int expInt;
                try
                {
                    expInt = Convert.ToInt32(expObj);
                }
                catch
                {
                    throw new SignatureVerificationException("Claim 'exp' must be an integer.");
                }

                if (secondsSinceEpoch >= expInt)
                {
                    throw new TokenExpiredException("Token has expired.")
                    {
                        Expiration = UnixEpoch.AddSeconds(expInt),
                        PayloadData = payloadData
                    };
                }
            }

            // verify nbf claim https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.5
            object nbfObj;
            if (payloadData.TryGetValue("nbf", out nbfObj))
            {
                int nbfInt;
                try
                {
                    nbfInt = Convert.ToInt32(nbfObj);
                }
                catch
                {
                    throw new SignatureVerificationException("Claim 'nbf' must be an integer.");
                }

                if (secondsSinceEpoch < nbfInt)
                {
                    throw new SignatureVerificationException("Token is not yet valid.");
                }
            }
        }

        /// <remarks>In the future this method can be open for extension so made protected virtual</remarks>
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
    }
}