using System;
using System.Collections.Generic;

namespace JWT
{
    public sealed class JwtValidator : IJwtValidator
    {
        private static readonly DateTime _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        private readonly IJsonSerializer _jsonSerializer;

        public JwtValidator(IJsonSerializer jsonSerializer)
        {
            _jsonSerializer = jsonSerializer;
        }

        /// <inheritdoc />
        public void Validate(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            if (decodedCrypto != decodedSignature)
            {
                throw new SignatureVerificationException("Invalid signature")
                {
                    Expected = decodedCrypto,
                    Received = decodedSignature
                };
            }

            // verify exp claim https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4
            var payloadData = _jsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
            object expObj;
            if (!payloadData.TryGetValue("exp", out expObj) || expObj == null)
            {
                return;
            }
            int expInt;
            try
            {
                expInt = Convert.ToInt32(expObj);
            }
            catch (FormatException)
            {
                throw new SignatureVerificationException("Claim 'exp' must be an integer.");
            }
            var secondsSinceEpoch = Math.Round((DateTime.UtcNow - _unixEpoch).TotalSeconds);
            if (secondsSinceEpoch >= expInt)
            {
                throw new TokenExpiredException("Token has expired.")
                {
                    Expiration = _unixEpoch.AddSeconds(expInt),
                    PayloadData = payloadData
                };
            }
        }
    }
}