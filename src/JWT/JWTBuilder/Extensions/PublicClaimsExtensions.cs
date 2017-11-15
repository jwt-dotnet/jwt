using JWT.JwtBuilder.Enums;
using System;

namespace JWT.JwtBuilder.Extensions
{
    public static class PublicClaimsExtensions
    {
        public static Builder ExpirationTime(this Builder builder, DateTime time)
        {
            return builder.AddClaim(PublicClaimsNames.ExpirationTime, GetSecoundsSinceEpocheAsString(time));
        }

        public static Builder Issuer(this Builder builder, string issuer)
        {
            return builder.AddClaim(PublicClaimsNames.Issuer, issuer);
        }

        public static Builder Subject(this Builder builder, string subject)
        {
            return builder.AddClaim(PublicClaimsNames.Subject, subject);
        }

        public static Builder Audience(this Builder builder, string audience)
        {
            return builder.AddClaim(PublicClaimsNames.Audience, audience);
        }

        public static Builder NotBefore(this Builder builder, DateTime time)
        {
            return builder.AddClaim(PublicClaimsNames.NotBefore, GetSecoundsSinceEpocheAsString(time));
        }

        public static Builder IssuedAt(this Builder builder, DateTime time)
        {
            return builder.AddClaim(PublicClaimsNames.IssuedAt, GetSecoundsSinceEpocheAsString(time));
        }

        public static Builder Id(this Builder builder, Guid id)
        {
            return builder.AddClaim(PublicClaimsNames.JWTID, id.ToString());
        }

        public static Builder Id(this Builder builder, long id)
        {
            return builder.AddClaim(PublicClaimsNames.JWTID, id.ToString());
        }

        public static Builder Id(this Builder builder, string id)
        {
            return builder.AddClaim(PublicClaimsNames.JWTID, id);
        }

        public static Builder GivenName(this Builder builder, string name)
        {
            return builder.AddClaim(PublicClaimsNames.GivenName, name);
        }

        public static Builder SurName(this Builder builder, string lastname)
        {
            return builder.AddClaim(PublicClaimsNames.SurName, lastname);
        }

        public static Builder MiddleName(this Builder builder, string middleName)
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