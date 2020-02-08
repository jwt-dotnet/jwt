using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace JWT.Builder
{
    public static class JwtBuilderExtensions
    {
        /// <summary>
        /// Adds well-known claim to the JWT.
        /// </summary>
        public static JwtBuilder AddClaim(this JwtBuilder builder, ClaimName name, object value) =>
            builder.AddClaim(name.GetPublicClaimName(), value);

        /// <summary>
        /// Adds well-known claim to the JWT.
        /// </summary>
        public static JwtBuilder AddClaim<T>(this JwtBuilder builder, ClaimName name, T value) =>
            builder.AddClaim(name, (object)value);

        /// <summary>
        /// Adds well-known claim to the JWT.
        /// </summary>
        public static JwtBuilder AddClaim<T>(this JwtBuilder builder, string name, T value) =>
            builder.AddClaim(name, value);

        /// <summary>
        /// Adds several claims to the JWT
        /// </summary>
        public static JwtBuilder AddClaims(this JwtBuilder builder, IEnumerable<KeyValuePair<string, object>> claims) =>
            claims.Aggregate(builder, (b, p) => b.AddClaim(p.Key, p.Value));

        public static JwtBuilder ExpirationTime(this JwtBuilder builder, DateTime time) =>
            builder.AddClaim(ClaimName.ExpirationTime, UnixEpoch.GetSecondsSince(time));

        public static JwtBuilder ExpirationTime(this JwtBuilder builder, long time) =>
            builder.AddClaim(ClaimName.ExpirationTime, time);

        public static JwtBuilder Issuer(this JwtBuilder builder, string issuer) =>
            builder.AddClaim(ClaimName.Issuer, issuer);

        public static JwtBuilder Subject(this JwtBuilder builder, string subject) =>
            builder.AddClaim(ClaimName.Subject, subject);

        public static JwtBuilder Audience(this JwtBuilder builder, string audience) =>
            builder.AddClaim(ClaimName.Audience, audience);

        public static JwtBuilder NotBefore(this JwtBuilder builder, DateTime time) =>
            builder.AddClaim(ClaimName.NotBefore, UnixEpoch.GetSecondsSince(time));

        public static JwtBuilder NotBefore(this JwtBuilder builder, long time) =>
            builder.AddClaim(ClaimName.NotBefore, time);

        public static JwtBuilder IssuedAt(this JwtBuilder builder, DateTime time) =>
            builder.AddClaim(ClaimName.IssuedAt, UnixEpoch.GetSecondsSince(time));

        public static JwtBuilder IssuedAt(this JwtBuilder builder, long time) =>
            builder.AddClaim(ClaimName.IssuedAt, time);

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
