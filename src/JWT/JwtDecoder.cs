using System;
using System.Collections.Generic;
using System.Text;

namespace JWT
{
    public class JwtDecoder : IJwtDecoder
    {
        /// <inheritdoc />
        public string Decode(string token, string key, bool verify = true)
        {
            return Decode(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <inheritdoc />
        public string Decode(string token, byte[] key, bool verify = true)
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                throw new ArgumentException("Token must consist from 3 delimited by dot parts");
            }

            var payload = parts[1];
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));

            if (verify)
            {
                Verify(payload, payloadJson, parts, key);
            }

            return payloadJson;
        }

        /// <inheritdoc />
        public object DecodeToObject(string token, string key, bool verify = true)
        {
            return DecodeToObject(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <inheritdoc />
        public object DecodeToObject(string token, byte[] key, bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            return JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
        }

        /// <inheritdoc />
        public T DecodeToObject<T>(string token, string key, bool verify = true)
        {
            return DecodeToObject<T>(token, Encoding.UTF8.GetBytes(key), verify);
        }

        /// <inheritdoc />
        public T DecodeToObject<T>(string token, byte[] key, bool verify = true)
        {
            var payloadJson = Decode(token, key, verify);
            return JsonSerializer.Deserialize<T>(payloadJson);
        }
    }
}