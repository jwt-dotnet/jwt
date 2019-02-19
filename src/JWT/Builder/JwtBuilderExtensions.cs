using System;
using System.Globalization;

namespace JWT.Builder
{
    public static class JwtBuilderExtensions
    {
        public static JwtBuilder ExpirationTime(this JwtBuilder builder, DateTime time) =>
			builder.AddClaim(ClaimName.ExpirationTime, UnixEpoch.GetSecondsSinceAsString(time));

        public static JwtBuilder Issuer(this JwtBuilder builder, string issuer) =>
			builder.AddClaim(ClaimName.Issuer, issuer);

        public static JwtBuilder Subject(this JwtBuilder builder, string subject) =>
			builder.AddClaim(ClaimName.Subject, subject);

        public static JwtBuilder Audience(this JwtBuilder builder, string audience) =>
			builder.AddClaim(ClaimName.Audience, audience);

        public static JwtBuilder NotBefore(this JwtBuilder builder, DateTime time) =>
			builder.AddClaim(ClaimName.NotBefore, UnixEpoch.GetSecondsSinceAsString(time));

        public static JwtBuilder IssuedAt(this JwtBuilder builder, DateTime time) =>
			builder.AddClaim(ClaimName.IssuedAt, UnixEpoch.GetSecondsSinceAsString(time));

        public static JwtBuilder Id(this JwtBuilder builder, Guid id) =>
			builder.Id(id.ToString());

        public static JwtBuilder Id(this JwtBuilder builder, long id) =>
			builder.Id(id.ToString(CultureInfo.InvariantCulture));

        public static JwtBuilder Id(this JwtBuilder builder, string id) =>
			builder.AddClaim(ClaimName.JwtId, id);

        public static JwtBuilder GivenName(this JwtBuilder builder, string name) =>
			builder.AddClaim(ClaimName.GivenName, name);

        public static JwtBuilder FamilyName(this JwtBuilder builder, string lastname) =>
			builder.AddClaim(ClaimName.FamilyName, lastname);

        public static JwtBuilder MiddleName(this JwtBuilder builder, string middleName) =>
			builder.AddClaim(ClaimName.MiddleName, middleName);
    }
}