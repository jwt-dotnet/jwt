using System.ComponentModel;

namespace JWT.Builder.Enums
{
    /// <summary>
    /// All Public Claims of a JWT, specified by IANA, see https://www.iana.org/assignments/jwt/jwt.xhtml
    /// </summary>
    /// <remarks>
    /// Latest update: 31.10.2017
    /// </remarks>
    public enum PublicClaimsNames
    {
        [Description("iss")]
        Issuer,
        [Description("sub")]
        Subject,
        [Description("aud")]
        Audience,
        [Description("exp")]
        ExpirationTime,
        [Description("nbf")]
        NotBefore,
        [Description("iat")]
        IssuedAt,
        [Description("jti")]
        JWTID,
        [Description("name")]
        FullName,
        [Description("given_name")]
        GivenName,
        [Description("family_name")]
        SurName,
        [Description("middle_name")]
        MiddleName,
        [Description("nickname")]
        CasualName,
        [Description("preferred_username")]
        PreferredUsername,
        [Description("profile")]
        ProfilePageUrl,
        [Description("picture")]
        ProfilPictureUrl,
        [Description("website")]
        WebSite,
        [Description("email")]
        PreferredEmail,
        [Description("email_verified")]
        VerifiedEmail,
        [Description("gender")]
        Gender,
        [Description("birthdate")]
        Birthday,
        [Description("zoneinfo")]
        TimeZone,
        [Description("locale")]
        Locale,
        [Description("phone_number")]
        PreferredPhoneNumber,
        [Description("phone_number_verified")]
        VerifiedPhoneNumber,
        [Description("address")]
        Address,
        [Description("update_at")]
        UpdatedAt,
        [Description("azp")]
        AuthorizedParty,
        [Description("nonce")]
        Nonce,
        [Description("auth_time")]
        AuthTime,
        [Description("at_hash")]
        AccessTokenHash,
        [Description("c_hash")]
        CodeHashValue,
        [Description("acr")]
        Acr,
        [Description("amr")]
        Amr,
        [Description("sub_jwk")]
        PublicKey,
        [Description("cnf")]
        Confirmation,
        [Description("sip_from_tag")]
        SipFromTag,
        [Description("sip_date")]
        SipDate,
        [Description("sip_callid")]
        SipCallId,
        [Description("sip_cseq_num")]
        SipCseqNumber,
        [Description("sip_via_branch")]
        SipViaBranch,
        [Description("orig")]
        OriginatingIdentityString,
        [Description("dest")]
        DestinationIdentityString,
        [Description("mky")]
        MediaKeyFingerprintString
    }
}