using System.Collections.Generic;
namespace JWT.JWTBuilder.Models
{

    /// <summary>
    /// Represents the Data that will store in a JWT.
    /// </summary>
    public class JWTData
    {
        /// <summary>
        /// Create a new instance of JWTData and initalize Header and Payload.
        /// </summary>
        /// <returns>A Instance of <see cref"JWTData"/></returns>
        public JWTData() : this(Header: new Dictionary<string, string>(), PayLoad: new Dictionary<string, object>())
        {
        }

        /// <summary>
        /// Create a new instance of JWTData
        /// </summary>
        /// <param name="Header">A Instance of a dictionary that contains the headers</param>
        /// <param name="PayLoad">A instance of a dictionary that contans the payload</param>
        public JWTData(Dictionary<string, string> Header, Dictionary<string, object> PayLoad)
        {
            this.Header = Header;
            this.PayLoad = PayLoad;
        }

        /// <summary>
        /// The header information as a key, value store of the JWT
        /// </summary>
        /// <returns>The headers of the JWT</returns>
        public Dictionary<string, string> Header { get; set; }
        /// <summary>
        /// The payload of the JWT as a key,value store
        /// </summary>
        /// <returns>The payload of the JWT</returns>
        public Dictionary<string, object> PayLoad { get; set; }

    }
}