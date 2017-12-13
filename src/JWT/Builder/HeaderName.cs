using System.ComponentModel;

namespace JWT.Builder
{
    /// <summary>
    /// All predefined headers specified by RFC 7519, see https://tools.ietf.org/html/rfc7519
    /// </summary>
    /// <remarks>
    /// Latest update: 31.10.2017
    /// </remarks>
    public enum HeaderName
    {
        [Description("typ")]
        Type,

        [Description("cty")]
        ContentType,

        [Description("alg")]
        Algorithm
    }
}