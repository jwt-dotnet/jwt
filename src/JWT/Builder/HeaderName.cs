using System.ComponentModel;

namespace JWT.Builder
{
    /// <summary>
    /// All predefined parameter names specified by RFC 7515, see https://tools.ietf.org/html/rfc7515
    /// </summary>
    public enum HeaderName
    {
        [Description("typ")]
        Type,

        [Description("cty")]
        ContentType,

        [Description("alg")]
        Algorithm,

        [Description("kid")]
        KeyId,

        [Description("x5u")]
        X5u,

        [Description("x5c")]
        X5c,

        [Description("x5t")]
        X5t
    }
}