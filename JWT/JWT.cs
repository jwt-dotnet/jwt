using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JWT
{
	public enum JwtHashAlgorithm
	{
		HS256,
		HS384,
		HS512
	}

	public class JWT
	{
		private static Dictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>> HashAlgorithms;

		static JWT()
		{
			HashAlgorithms = new Dictionary<JwtHashAlgorithm, Func<byte[], byte[], byte[]>>
			{
				{ JwtHashAlgorithm.HS256, (key, value) => { using (var sha = new HMACSHA256(key)) { return sha.ComputeHash(value); } } },
				{ JwtHashAlgorithm.HS384, (key, value) => { using (var sha = new HMACSHA384(key)) { return sha.ComputeHash(value); } } },
				{ JwtHashAlgorithm.HS512, (key, value) => { using (var sha = new HMACSHA512(key)) { return sha.ComputeHash(value); } } }
			};
		}

		public static string Encode(object payload, string key, JwtHashAlgorithm algorithm)
		{
			var segments = new List<string>();
			var header = new { typ = "JWT", alg = algorithm.ToString() };

			segments.Add(Base64UrlEncode(JsonConvert.SerializeObject(header, Formatting.Indented)));
			segments.Add(Base64UrlEncode(JsonConvert.SerializeObject(payload, Formatting.Indented)));

			var stringToSign = string.Join(".", segments.ToArray());

			var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);
			var keyBytes = Encoding.UTF8.GetBytes(key);

			var signature = HashAlgorithms[algorithm](keyBytes, bytesToSign);
			segments.Add(Base64UrlEncode(Encoding.UTF8.GetString(signature)));

			return string.Join(".", segments.ToArray());
		}

		public static string Decode(string token, string key)
		{
			return Decode(token, key, true);
		}

		public static string Decode(string token, string key, bool verify)
		{
			var parts = token.Split('.');
			var header = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
			var payload = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
			var crypto = Base64UrlDecode(parts[2]);

			var json = new JsonSerializer();

			var headerData = JObject.Parse(header);
			var payloadData = JObject.Parse(payload);

			if (verify)
			{
				var bytesToSign = Encoding.UTF8.GetBytes(string.Concat(header, ".", payload));
				var keyBytes = Encoding.UTF8.GetBytes(key);
				var algorithm = (string)headerData["alg"];

				var signature = HashAlgorithms[GetHashAlgorithm(algorithm)](keyBytes, bytesToSign);

				if (crypto != signature)
				{
					throw new ApplicationException("Invalid signature");
				}
			}

			return payloadData.ToString();
		}

		private static JwtHashAlgorithm GetHashAlgorithm(string algorithm)
		{
			switch (algorithm)
			{
				case "HS256": return JwtHashAlgorithm.HS256;
				case "HS384": return JwtHashAlgorithm.HS384;
				case "HS512": return JwtHashAlgorithm.HS512;
				default: throw new InvalidOperationException("Algorithm not supported.");
			}
		}

		// from JWT spec
		public static string Base64UrlEncode(string input)
		{
			var inputBytes = Encoding.UTF8.GetBytes(input);
			var output = Convert.ToBase64String(inputBytes);
			output = output.Split('=')[0]; // Remove any trailing '='s
			output = output.Replace('+', '-'); // 62nd char of encoding
			output = output.Replace('/', '_'); // 63rd char of encoding
			return output;
		}

		// from JWT spec
		public static byte[] Base64UrlDecode(string input)
		{
			var output = input;
			output = output.Replace('-', '+'); // 62nd char of encoding
			output = output.Replace('_', '/'); // 63rd char of encoding
			switch (output.Length % 4) // Pad with trailing '='s
			{
				case 0: break; // No pad chars in this case
				case 2: output += "=="; break; // Two pad chars
				case 3: output += "="; break; // One pad char
				default: throw new System.Exception("Illegal base64url string!");
			}
			return Convert.FromBase64String(output); // Standard base64 decoder
		}
	}

}
