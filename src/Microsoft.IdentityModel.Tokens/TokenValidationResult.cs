//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains artifacts obtained when a SecurityToken is validated.
    /// </summary>
    public class TokenValidationResult
    {
        private Lazy<IDictionary<string, object>> _claims;
        private Lazy<ClaimsIdentity> _claimsIdentity;

        private IClaimProvider _claimProvider;
        private ClaimsIdentity _ciSet;
        private bool _wasClaimsIdentitySet;
        private TokenValidationParameters _validationParameters;

        /// <summary>
        ///
        /// </summary>
        public TokenValidationResult()
        {
            _claims = new Lazy<IDictionary<string, object>>(() => TokenUtilities.CreateDictionaryFromClaims(ClaimsIdentity?.Claims));
        }

        internal TokenValidationResult(SecurityToken securityToken, TokenValidationParameters validationParameters, string issuer)
        {
            _validationParameters = validationParameters;
            _claimProvider = securityToken as IClaimProvider;
            Issuer = issuer;
            SecurityToken = securityToken;
             _claimsIdentity = new Lazy<ClaimsIdentity>(() => ClaimsIdentityFactory());
            _claims = new Lazy<IDictionary<string, object>>(() => TokenUtilities.CreateDictionaryFromClaims(ClaimsIdentity?.Claims));
        }

        /// <summary>
        /// The <see cref="Dictionary{String, Object}"/> created from the validated security token.
        /// </summary>
        public IDictionary<string, object> Claims
        {
            get
            {
                return _claims.Value;
            }
        }

        /// <summary>
        /// The <see cref="ClaimsIdentity"/> created from the validated security token.
        /// </summary>
        public ClaimsIdentity ClaimsIdentity
        {
            get
            {
                if (_wasClaimsIdentitySet)
                    return _ciSet;

                if (_claimProvider != null)
                    return _claimsIdentity.Value;

                return null;
            }

            set
            {
                _ciSet = value;
                _wasClaimsIdentitySet = true;
            }
        }

        private ClaimsIdentity ClaimsIdentityFactory()
        {
            ClaimsIdentity claimsIdentity = _validationParameters.CreateClaimsIdentity(SecurityToken, Issuer);
            foreach (Claim jwtClaim in _claimProvider.Claims)
            {
                string claimType = jwtClaim.Type;
                // TODO this is not the actor token, need to create the SecurityToken representing actor.
                if (claimType == ClaimTypes.Actor)
                {
                    if (claimsIdentity.Actor != null)
                        throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant("LogMessages.IDX14112, JwtRegisteredClaimNames.Actort, jwtClaim.Value")));

                    ClaimsIdentity actorClaimsIdentity = _validationParameters.CreateClaimsIdentity(SecurityToken, Issuer);
                    foreach (Claim actClaim in _claimProvider.ActorClaims)
                    {
                        AddClaim(claimsIdentity, actClaim);
                    }

                    claimsIdentity.Actor = actorClaimsIdentity;
                }

                AddClaim(claimsIdentity, jwtClaim);
            }

            return claimsIdentity;
        }

        private void AddClaim(ClaimsIdentity ci, Claim claim)
        {
            if (claim.Properties.Count == 0)
            {
                ci.AddClaim(new Claim(claim.Type, claim.Value, claim.ValueType, Issuer, Issuer, ci));
            }
            else
            {
                Claim c = new Claim(claim.Type, claim.Value, claim.ValueType, Issuer, Issuer, ci);
                foreach (var kv in claim.Properties)
                    c.Properties[kv.Key] = kv.Value;

                ci.AddClaim(c);
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="Exception"/> that occurred during validation.
        /// </summary>
        public Exception Exception { get; set; }

        /// <summary>
        /// Gets or sets the issuer that was found in the token.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// True if the token was successfully validated, false otherwise.
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IDictionary{String, Object}"/> that contains a collection of custom key/value pairs. This allows addition of data that could be used in custom scenarios. This uses <see cref="StringComparer.Ordinal"/> for case-sensitive comparison of keys.
        /// </summary>
        public IDictionary<string, object> PropertyBag { get; } = new Dictionary<string, object>(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the <see cref="SecurityToken"/> that was validated.
        /// </summary>
        public SecurityToken SecurityToken { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="CallContext"/> that contains call information.
        /// </summary>
        public CallContext TokenContext { get; set; }

        /// <summary>
        /// Gets or sets the token type of the <see cref="SecurityToken"/> that was validated.
        /// When a <see cref="TokenValidationParameters.TypeValidator"/> is registered,
        /// the type returned by the delegate is used to populate this property.
        /// Otherwise, the type is resolved from the token itself, if available
        /// (e.g for a JSON Web Token, from the "typ" header). 
        /// </summary>
        public string TokenType { get; set; }
    }
}
