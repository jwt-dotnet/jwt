using JWT.Builder.Enums;
using System;

namespace JWT.Builder.Extensions
{
    public static class PublicClaimsExtensions
    {
        public static JwtBuilder ExpirationTime(this JwtBuilder builder, DateTime time)
        {   
            return builder.AddClaim(PublicClaimsNames.ExpirationTime, GetSecoundsSinceEpocheAsString(time));            
        }

        public static JwtBuilder Issuer(this JwtBuilder builder, string issuer)
        {
            return builder.AddClaim(PublicClaimsNames.Issuer, issuer);
        }

        public static JwtBuilder Subject(this JwtBuilder builder, string subject)
        {
            return builder.AddClaim(PublicClaimsNames.Subject, subject);
        }

        public static JwtBuilder Audience(this JwtBuilder builder, string audience)
        {
            return builder.AddClaim(PublicClaimsNames.Audience, audience);
        }

        public static JwtBuilder NotBefore(this JwtBuilder builder, DateTime time)
        {
            return builder.AddClaim(PublicClaimsNames.NotBefore, GetSecoundsSinceEpocheAsString(time));
        }

        public static JwtBuilder IssuedAt(this JwtBuilder builder, DateTime time)
        {
            return builder.AddClaim(PublicClaimsNames.IssuedAt, GetSecoundsSinceEpocheAsString(time));
        }
        public static JwtBuilder Id(this JwtBuilder builder, Guid id)
        {
            return builder.AddClaim(PublicClaimsNames.JWTID, id.ToString());
        }

        public static JwtBuilder Id(this JwtBuilder builder, long id)
        {
            return builder.AddClaim(PublicClaimsNames.JWTID, id.ToString());
        }
        public static JwtBuilder Id(this JwtBuilder builder, string id)
        {
            return builder.AddClaim(PublicClaimsNames.JWTID, id);
        }

        public static JwtBuilder GivenName(this JwtBuilder builder, string name)
        {
            return builder.AddClaim(PublicClaimsNames.GivenName, name);
        }

        public static JwtBuilder SurName(this JwtBuilder builder, string lastname)
        {
            return builder.AddClaim(PublicClaimsNames.SurName, lastname);
        }

        public static JwtBuilder MiddleName(this JwtBuilder builder, string middleName)
        {
            return builder.AddClaim(PublicClaimsNames.MiddleName, middleName);
        }

        private static double GetSecoundsSinceEpoche(DateTime time)
        {
            var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return Math.Round((time - unixEpoch).TotalSeconds);
        }

        private static string GetSecoundsSinceEpocheAsString(DateTime time)
        {
            return GetSecoundsSinceEpoche(time).ToString();
        }
    }
}