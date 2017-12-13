using System;

namespace JWT.Builder
{
    public static class PublicClaimsExtensions
    {
        public static JwtBuilder ExpirationTime(this JwtBuilder builder, DateTime time)
        {
            return builder.AddClaim(ClaimName.ExpirationTime, GetSecoundsSinceEpocheAsString(time));
        }

        public static JwtBuilder Issuer(this JwtBuilder builder, string issuer)
        {
            return builder.AddClaim(ClaimName.Issuer, issuer);
        }

        public static JwtBuilder Subject(this JwtBuilder builder, string subject)
        {
            return builder.AddClaim(ClaimName.Subject, subject);
        }

        public static JwtBuilder Audience(this JwtBuilder builder, string audience)
        {
            return builder.AddClaim(ClaimName.Audience, audience);
        }

        public static JwtBuilder NotBefore(this JwtBuilder builder, DateTime time)
        {
            return builder.AddClaim(ClaimName.NotBefore, GetSecoundsSinceEpocheAsString(time));
        }

        public static JwtBuilder IssuedAt(this JwtBuilder builder, DateTime time)
        {
            return builder.AddClaim(ClaimName.IssuedAt, GetSecoundsSinceEpocheAsString(time));
        }

        public static JwtBuilder Id(this JwtBuilder builder, Guid id)
        {
            return builder.AddClaim(ClaimName.JwtId, id.ToString());
        }

        public static JwtBuilder Id(this JwtBuilder builder, long id)
        {
            return builder.AddClaim(ClaimName.JwtId, id.ToString());
        }

        public static JwtBuilder Id(this JwtBuilder builder, string id)
        {
            return builder.AddClaim(ClaimName.JwtId, id);
        }

        public static JwtBuilder GivenName(this JwtBuilder builder, string name)
        {
            return builder.AddClaim(ClaimName.GivenName, name);
        }

        public static JwtBuilder SurName(this JwtBuilder builder, string lastname)
        {
            return builder.AddClaim(ClaimName.FamilyName, lastname);
        }

        public static JwtBuilder MiddleName(this JwtBuilder builder, string middleName)
        {
            return builder.AddClaim(ClaimName.MiddleName, middleName);
        }

        private static double GetSecoundsSinceEpoche(DateTime time)
        {
            return Math.Round((time - JwtValidator.UnixEpoch).TotalSeconds);
        }

        private static string GetSecoundsSinceEpocheAsString(DateTime time)
        {
            return GetSecoundsSinceEpoche(time).ToString();
        }
    }
}