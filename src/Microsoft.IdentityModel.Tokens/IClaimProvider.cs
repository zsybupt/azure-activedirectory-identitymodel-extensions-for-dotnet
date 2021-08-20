using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    ///
    /// </summary>
    public interface IClaimsIdentityProvider
    {
        /// <summary>
        /// 
        /// </summary>
        ClaimsIdentity ClaimsIdentity { get; }
    }

    /// <summary>
    ///
    /// </summary>
    public interface IClaimProvider
    {
        /// <summary>
        /// 
        /// </summary>
        IEnumerable<Claim> Claims { get; }

        /// <summary>
        ///
        /// </summary>
        IEnumerable<Claim> ActorClaims { get; }
    }
}
