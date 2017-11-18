using System.ComponentModel;

namespace JWT.Builder.Enums
{
    /// <summary>
    /// All predefined Headers specified by RFC. (https://tools.ietf.org/html/rfc7519)
    /// Last update 31.10.2017
    /// </summary>
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