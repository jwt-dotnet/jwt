using JWT.Builder;

namespace JWT
{
    public class JwtDecoderContext
    {
        /// <summary>
        /// Unmodified JWT.
        /// </summary>
        public JwtParts Token { get; set; }

        /// <summary>
        /// Deserialized JWT header.
        /// </summary>
        public JwtHeader Header { get; set; }

        /// <summary>
        /// Decoded JWT payload.
        /// </summary>
        public string Payload { get; set; }

        public static JwtDecoderContext Create(JwtHeader header, string decodedPayload, JwtParts jwt) =>
            new JwtDecoderContext
            {
                Token = jwt,
                Header = header,
                Payload = decodedPayload
            };
    }
}