﻿//------------------------------------------------------------------------------
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
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Json Web Tokens. 
    /// See: http://tools.ietf.org/html/rfc7519 and http://www.rfc-editor.org/info/rfc7515.
    /// </summary>
    public class JsonWebTokenHandler : TokenHandler
    {
        /// <summary>
        /// Gets the Base64Url encoded string representation of the following JWT header: 
        /// { <see cref="JwtHeaderParameterNames.Alg"/>, <see cref="SecurityAlgorithms.None"/> }.
        /// </summary>
        /// <return>The Base64Url encoded string representation of the unsigned JWT header.</return>
        public const string Base64UrlEncodedUnsignedJWSHeader = "eyJhbGciOiJub25lIn0";

        /// <summary>
        /// Gets the type of the <see cref="JsonWebToken"/>.
        /// </summary>
        /// <return>The type of <see cref="JsonWebToken"/></return>
        public Type TokenType
        {
            get { return typeof(JsonWebToken); }
        }

        /// <summary>
        /// Determines if the string is a well formed Json Web Token (JWT).
        /// <para>see: http://tools.ietf.org/html/rfc7519 </para>
        /// </summary>
        /// <param name="token">String that should represent a valid JWT.</param>
        /// <remarks>Uses <see cref="Regex.IsMatch(string, string)"/> matching:
        /// <para>JWS: @"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$"</para>
        /// <para>JWE: (dir): @"^[A-Za-z0-9-_]+\.\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$"</para>
        /// <para>JWE: (wrappedkey): @"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]$"</para>
        /// </remarks>
        /// <returns>
        /// <para>'false' if the token is null or whitespace.</para>
        /// <para>'false' if token.Length is greater than <see cref="TokenHandler.MaximumTokenSizeInBytes"/>.</para>
        /// <para>'true' if the token is in JSON compact serialization format.</para>
        /// </returns>
        public virtual bool CanReadToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return false;

            if (token.Length > MaximumTokenSizeInBytes)
            {
                LogHelper.LogInformation(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes);
                return false;
            }

            // Set the maximum number of segments to MaxJwtSegmentCount + 1. This controls the number of splits and allows detecting the number of segments is too large.
            // For example: "a.b.c.d.e.f.g.h" => [a], [b], [c], [d], [e], [f.g.h]. 6 segments.
            // If just MaxJwtSegmentCount was used, then [a], [b], [c], [d], [e.f.g.h] would be returned. 5 segments.
            string[] tokenParts = token.Split(new char[] { '.' }, JwtConstants.MaxJwtSegmentCount + 1);
            if (tokenParts.Length == JwtConstants.JwsSegmentCount)
                return JwtTokenUtilities.RegexJws.IsMatch(token);
            else if (tokenParts.Length == JwtConstants.JweSegmentCount)
                return JwtTokenUtilities.RegexJwe.IsMatch(token);

            LogHelper.LogInformation(LogMessages.IDX14107);
            return false;
        }

        /// <summary>
        /// Returns a value that indicates if this handler can validate a <see cref="SecurityToken"/>.
        /// </summary>
        /// <returns>'true', indicating this instance can validate a <see cref="JsonWebToken"/>.</returns>
        public virtual bool CanValidateToken
        {
            get { return true; }
        }

        private static JObject CreateDefaultJWEHeader(EncryptingCredentials encryptingCredentials, string compressionAlgorithm, string tokenType)
        {
            var header = new JObject();
            header.Add(JwtHeaderParameterNames.Alg, encryptingCredentials.Alg);
            header.Add(JwtHeaderParameterNames.Enc, encryptingCredentials.Enc);

            if (!string.IsNullOrEmpty(encryptingCredentials.Key.KeyId))
                header.Add(JwtHeaderParameterNames.Kid, encryptingCredentials.Key.KeyId);

            if (!string.IsNullOrEmpty(compressionAlgorithm))
                header.Add(JwtHeaderParameterNames.Zip, compressionAlgorithm);

            if (string.IsNullOrEmpty(tokenType))
                header.Add(JwtHeaderParameterNames.Typ, JwtConstants.HeaderType);
            else
                header.Add(JwtHeaderParameterNames.Typ, tokenType);

            return header;
        }

        private static JObject CreateDefaultJWSHeader(SigningCredentials signingCredentials, string tokenType)
        {
            JObject header = null;

            if (signingCredentials == null)
            {
                header = new JObject()
                {
                    {JwtHeaderParameterNames.Alg, SecurityAlgorithms.None }
                };
            }
            else
            {
                header = new JObject()
                {
                    { JwtHeaderParameterNames.Alg, signingCredentials.Algorithm }
                };

                if (signingCredentials.Key.KeyId != null)
                    header.Add(JwtHeaderParameterNames.Kid, signingCredentials.Key.KeyId);

                if (signingCredentials.Key is X509SecurityKey x509SecurityKey)
                    header[JwtHeaderParameterNames.X5t] = x509SecurityKey.X5t;
            }

            if (string.IsNullOrEmpty(tokenType))
                header.Add(JwtHeaderParameterNames.Typ, JwtConstants.HeaderType);
            else
                header.Add(JwtHeaderParameterNames.Typ, tokenType);

            return header;
        }

        /// <summary>
        /// Creates an unsigned JWS (Json Web Signature).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="payload"/> is null.</exception>
        /// <returns>A JWS in Compact Serialization Format.</returns>
        public virtual string CreateToken(string payload)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            return CreateTokenPrivate(JObject.Parse(payload), null, null, null, null, null);
        }

        /// <summary>
        /// Creates an unsigned JWS (Json Web Signature).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <param name="additionalHeaderClaims">Defines the dictionary containing any custom header claims that need to be added to the JWT token header.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="payload"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="additionalHeaderClaims"/> is null.</exception>
        /// <returns>A JWS in Compact Serialization Format.</returns>
        public virtual string CreateToken(string payload, IDictionary<string, object> additionalHeaderClaims)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (additionalHeaderClaims == null)
                throw LogHelper.LogArgumentNullException(nameof(additionalHeaderClaims));

            return CreateTokenPrivate(JObject.Parse(payload), null, null, null, additionalHeaderClaims, null);
        }

        /// <summary>
        /// Creates a JWS (Json Web Signature).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <param name="signingCredentials">Defines the security key and algorithm that will be used to sign the JWS.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="payload"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signingCredentials"/> is null.</exception>
        /// <returns>A JWS in Compact Serialization Format.</returns>
        public virtual string CreateToken(string payload, SigningCredentials signingCredentials)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            return CreateTokenPrivate(JObject.Parse(payload), signingCredentials, null, null, null, null);
        }

        /// <summary>
        /// Creates a JWS (Json Web Signature).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <param name="signingCredentials">Defines the security key and algorithm that will be used to sign the JWS.</param>
        /// <param name="additionalHeaderClaims">Defines the dictionary containing any custom header claims that need to be added to the JWT token header.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="payload"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="additionalHeaderClaims"/> is null.</exception>
        /// <exception cref="SecurityTokenException">if <see cref="JwtHeaderParameterNames.Alg"/>, <see cref="JwtHeaderParameterNames.Kid"/>
        /// <see cref="JwtHeaderParameterNames.X5t"/>, <see cref="JwtHeaderParameterNames.Enc"/>, and/or <see cref="JwtHeaderParameterNames.Zip"/>
        /// are present inside of <paramref name="additionalHeaderClaims"/>.</exception>
        /// <returns>A JWS in Compact Serialization Format.</returns>
        public virtual string CreateToken(string payload, SigningCredentials signingCredentials, IDictionary<string, object> additionalHeaderClaims)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            if (additionalHeaderClaims == null)
                throw LogHelper.LogArgumentNullException(nameof(additionalHeaderClaims));

            return CreateTokenPrivate(JObject.Parse(payload), signingCredentials, null, null, additionalHeaderClaims, null);
        }

        /// <summary>
        /// Creates a JWS(Json Web Signature).
        /// </summary>
        /// <param name="tokenDescriptor">A <see cref="SecurityTokenDescriptor"/> that contains details of contents of the token.</param>
        /// <returns>A JWS in Compact Serialization Format.</returns>
        public virtual string CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            if (tokenDescriptor == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenDescriptor));

            if ((tokenDescriptor.Subject == null || !tokenDescriptor.Subject.Claims.Any())
                && (tokenDescriptor.Claims == null || !tokenDescriptor.Claims.Any()))
                LogHelper.LogWarning(LogMessages.IDX14114, nameof(SecurityTokenDescriptor), nameof(SecurityTokenDescriptor.Subject), nameof(SecurityTokenDescriptor.Claims));

            JObject payload;
            if (tokenDescriptor.Subject != null)
                payload = JObject.FromObject(TokenUtilities.CreateDictionaryFromClaims(tokenDescriptor.Subject.Claims));
            else
                payload = new JObject();

            // If a key is present in both tokenDescriptor.Subject.Claims and tokenDescriptor.Claims, the value present in tokenDescriptor.Claims is the
            // one that takes precedence and will remain after the merge. Key comparison is case sensitive. 
            if (tokenDescriptor.Claims != null && tokenDescriptor.Claims.Count > 0)
                payload.Merge(JObject.FromObject(tokenDescriptor.Claims), new JsonMergeSettings { MergeArrayHandling = MergeArrayHandling.Replace });

            if (tokenDescriptor.Audience != null)
            {
                if (payload.ContainsKey(JwtRegisteredClaimNames.Aud))
                    LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX14113, nameof(tokenDescriptor.Audience)));

                payload[JwtRegisteredClaimNames.Aud] = tokenDescriptor.Audience;
            }

            if (tokenDescriptor.Expires.HasValue)
            {
                if (payload.ContainsKey(JwtRegisteredClaimNames.Exp))
                    LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX14113, nameof(tokenDescriptor.Expires)));

                payload[JwtRegisteredClaimNames.Exp] = EpochTime.GetIntDate(tokenDescriptor.Expires.Value);
            }

            if (tokenDescriptor.Issuer != null)
            {
                if (payload.ContainsKey(JwtRegisteredClaimNames.Iss))
                    LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX14113, nameof(tokenDescriptor.Issuer)));

                payload[JwtRegisteredClaimNames.Iss] = tokenDescriptor.Issuer;
            }

            if (tokenDescriptor.IssuedAt.HasValue)
            {
                if (payload.ContainsKey(JwtRegisteredClaimNames.Iat))
                    LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX14113, nameof(tokenDescriptor.IssuedAt)));

                payload[JwtRegisteredClaimNames.Iat] = EpochTime.GetIntDate(tokenDescriptor.IssuedAt.Value);
            }

            if (tokenDescriptor.NotBefore.HasValue)
            {
                if (payload.ContainsKey(JwtRegisteredClaimNames.Nbf))
                    LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX14113, nameof(tokenDescriptor.NotBefore)));

                payload[JwtRegisteredClaimNames.Nbf] = EpochTime.GetIntDate(tokenDescriptor.NotBefore.Value);
            }

            return CreateTokenPrivate(payload, tokenDescriptor.SigningCredentials, tokenDescriptor.EncryptingCredentials, tokenDescriptor.CompressionAlgorithm, tokenDescriptor.AdditionalHeaderClaims, tokenDescriptor.TokenType);
        }

        /// <summary>
        /// Creates a JWE (Json Web Encryption).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the JWT.</param>
        /// <returns>A JWE in compact serialization format.</returns>
        public virtual string CreateToken(string payload, EncryptingCredentials encryptingCredentials)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            return CreateTokenPrivate(JObject.Parse(payload), null, encryptingCredentials, null, null, null);
        }

        /// <summary>
        /// Creates a JWE (Json Web Encryption).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <param name="signingCredentials">Defines the security key and algorithm that will be used to sign the JWT.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the JWT.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="payload"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encryptingCredentials"/> is null.</exception>
        /// <returns>A JWE in compact serialization format.</returns>
        public virtual string CreateToken(string payload, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            return CreateTokenPrivate(JObject.Parse(payload), signingCredentials, encryptingCredentials, null, null, null);
        }

        /// <summary>
        /// Creates a JWE (Json Web Encryption).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <param name="signingCredentials">Defines the security key and algorithm that will be used to sign the JWT.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the JWT.</param>
        /// <param name="additionalHeaderClaims">Defines the dictionary containing any custom header claims that need to be added to the outer JWT token header.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="payload"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encryptingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="additionalHeaderClaims"/> is null.</exception>
        /// <exception cref="SecurityTokenException">if <see cref="JwtHeaderParameterNames.Alg"/>, <see cref="JwtHeaderParameterNames.Kid"/>
        /// <see cref="JwtHeaderParameterNames.X5t"/>, <see cref="JwtHeaderParameterNames.Enc"/>, and/or <see cref="JwtHeaderParameterNames.Zip"/>
        /// are present inside of <paramref name="additionalHeaderClaims"/>.</exception>
        /// <returns>A JWE in compact serialization format.</returns>
        public virtual string CreateToken(string payload, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials, IDictionary<string, object> additionalHeaderClaims)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            if (additionalHeaderClaims == null)
                throw LogHelper.LogArgumentNullException(nameof(additionalHeaderClaims));

            return CreateTokenPrivate(JObject.Parse(payload), signingCredentials, encryptingCredentials, null, additionalHeaderClaims, null);
        }

        /// <summary>
        /// Creates a JWE (Json Web Encryption).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the JWT.</param>
        /// <param name="compressionAlgorithm">Defines the compression algorithm that will be used to compress the JWT token payload.</param>
        /// <returns>A JWE in compact serialization format.</returns>
        public virtual string CreateToken(string payload, EncryptingCredentials encryptingCredentials, string compressionAlgorithm)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            if (string.IsNullOrEmpty(compressionAlgorithm))
                throw LogHelper.LogArgumentNullException(nameof(compressionAlgorithm));

            return CreateTokenPrivate(JObject.Parse(payload), null, encryptingCredentials, compressionAlgorithm, null, null);
        }

        /// <summary>
        /// Creates a JWE (Json Web Encryption).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <param name="signingCredentials">Defines the security key and algorithm that will be used to sign the JWT.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the JWT.</param>
        /// <param name="compressionAlgorithm">Defines the compression algorithm that will be used to compress the JWT token payload.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="payload"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encryptingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="compressionAlgorithm"/> is null.</exception>
        /// <returns>A JWE in compact serialization format.</returns>
        public virtual string CreateToken(string payload, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials, string compressionAlgorithm)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            if (string.IsNullOrEmpty(compressionAlgorithm))
                throw LogHelper.LogArgumentNullException(nameof(compressionAlgorithm));

            return CreateTokenPrivate(JObject.Parse(payload), signingCredentials, encryptingCredentials, compressionAlgorithm, null, null);
        }

        /// <summary>
        /// Creates a JWE (Json Web Encryption).
        /// </summary>
        /// <param name="payload">A string containing JSON which represents the JWT token payload.</param>
        /// <param name="signingCredentials">Defines the security key and algorithm that will be used to sign the JWT.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the JWT.</param>
        /// <param name="compressionAlgorithm">Defines the compression algorithm that will be used to compress the JWT token payload.</param>       
        /// <param name="additionalHeaderClaims">Defines the dictionary containing any custom header claims that need to be added to the outer JWT token header.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="payload"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encryptingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="compressionAlgorithm"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="additionalHeaderClaims"/> is null.</exception>
        /// <exception cref="SecurityTokenException">if <see cref="JwtHeaderParameterNames.Alg"/>, <see cref="JwtHeaderParameterNames.Kid"/>
        /// <see cref="JwtHeaderParameterNames.X5t"/>, <see cref="JwtHeaderParameterNames.Enc"/>, and/or <see cref="JwtHeaderParameterNames.Zip"/>
        /// are present inside of <paramref name="additionalHeaderClaims"/>.</exception>
        /// <returns>A JWE in compact serialization format.</returns>
        public virtual string CreateToken(string payload, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials, string compressionAlgorithm, IDictionary<string, object> additionalHeaderClaims)
        {
            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            if (string.IsNullOrEmpty(compressionAlgorithm))
                throw LogHelper.LogArgumentNullException(nameof(compressionAlgorithm));

            if (additionalHeaderClaims == null)
                throw LogHelper.LogArgumentNullException(nameof(additionalHeaderClaims));

            return CreateTokenPrivate(JObject.Parse(payload), signingCredentials, encryptingCredentials, compressionAlgorithm, additionalHeaderClaims, null);
        }

        private string CreateTokenPrivate(JObject payload, SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials, string compressionAlgorithm, IDictionary<string, object> additionalHeaderClaims, string tokenType)
        {
            if (additionalHeaderClaims?.Count > 0 && additionalHeaderClaims.Keys.Intersect(JwtTokenUtilities.DefaultHeaderParameters, StringComparer.OrdinalIgnoreCase).Any())
                throw LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(LogMessages.IDX14116, nameof(additionalHeaderClaims), string.Join(", ", JwtTokenUtilities.DefaultHeaderParameters))));

            var header = CreateDefaultJWSHeader(signingCredentials, tokenType);

            if (encryptingCredentials == null && additionalHeaderClaims != null && additionalHeaderClaims.Count > 0)
                header.Merge(JObject.FromObject(additionalHeaderClaims));

            var rawHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToString(Formatting.None)));

            if (SetDefaultTimesOnTokenCreation)
            {
                var now = EpochTime.GetIntDate(DateTime.UtcNow);
                if (!payload.TryGetValue(JwtRegisteredClaimNames.Exp, out _))
                    payload.Add(JwtRegisteredClaimNames.Exp, now + TokenLifetimeInMinutes * 60);

                if (!payload.TryGetValue(JwtRegisteredClaimNames.Iat, out _))
                    payload.Add(JwtRegisteredClaimNames.Iat, now);

                if (!payload.TryGetValue(JwtRegisteredClaimNames.Nbf, out _))
                    payload.Add(JwtRegisteredClaimNames.Nbf, now);
            }

            var rawPayload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload.ToString(Formatting.None)));
            var message = rawHeader + "." + rawPayload;
            var rawSignature = signingCredentials == null ? string.Empty : JwtTokenUtilities.CreateEncodedSignature(message, signingCredentials);

            if (encryptingCredentials != null)
                return EncryptTokenPrivate(message + "." + rawSignature, encryptingCredentials, compressionAlgorithm, additionalHeaderClaims, tokenType);

            return message + "." + rawSignature;
        }

        /// <summary>
        /// Compress a JWT token string.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="compressionAlgorithm"></param>
        /// <exception cref="ArgumentNullException">if <paramref name="token"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="compressionAlgorithm"/> is null.</exception>
        /// <exception cref="NotSupportedException">if the compression algorithm is not supported.</exception>
        /// <returns>Compressed JWT token bytes.</returns>
        private static byte[] CompressToken(string token, string compressionAlgorithm)
        {
            if (token == null)
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (string.IsNullOrEmpty(compressionAlgorithm))
                throw LogHelper.LogArgumentNullException(nameof(compressionAlgorithm));

            if (!CompressionProviderFactory.Default.IsSupportedAlgorithm(compressionAlgorithm))
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10682, compressionAlgorithm)));

            var compressionProvider = CompressionProviderFactory.Default.CreateCompressionProvider(compressionAlgorithm);

            return compressionProvider.Compress(Encoding.UTF8.GetBytes(token)) ?? throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(TokenLogMessages.IDX10680, compressionAlgorithm)));
        }

        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> from a <see cref="JsonWebToken"/>.
        /// </summary>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> to use as a <see cref="Claim"/> source.</param>
        /// <param name="validationParameters"> Contains parameters for validating the token.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> containing the <see cref="JsonWebToken.Claims"/>.</returns>
        protected virtual ClaimsIdentity CreateClaimsIdentity(JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (jwtToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            var actualIssuer = jwtToken.Issuer;
            if (string.IsNullOrWhiteSpace(actualIssuer))
            {
                LogHelper.LogVerbose(TokenLogMessages.IDX10244, ClaimsIdentity.DefaultIssuer);
                actualIssuer = ClaimsIdentity.DefaultIssuer;
            }

            return CreateClaimsIdentity(jwtToken, validationParameters, actualIssuer);
        }

        private ClaimsIdentity CreateClaimsIdentity(JsonWebToken jwtToken, TokenValidationParameters validationParameters, string actualIssuer)
        {
            ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(jwtToken, actualIssuer);
            foreach (Claim jwtClaim in jwtToken.Claims)
            {
                string claimType = jwtClaim.Type;
                if (claimType == ClaimTypes.Actor)
                {
                    if (identity.Actor != null)
                        throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX14112, JwtRegisteredClaimNames.Actort, jwtClaim.Value)));

                    if (CanReadToken(jwtClaim.Value))
                    {
                        JsonWebToken actor = ReadToken(jwtClaim.Value) as JsonWebToken;
                        identity.Actor = CreateClaimsIdentity(actor, validationParameters, actualIssuer);
                    }
                }

                if (jwtClaim.Properties.Count == 0)
                {
                    identity.AddClaim(new Claim(claimType, jwtClaim.Value, jwtClaim.ValueType, actualIssuer, actualIssuer, identity));
                }
                else
                {
                    Claim claim = new Claim(claimType, jwtClaim.Value, jwtClaim.ValueType, actualIssuer, actualIssuer, identity);

                    foreach (var kv in jwtClaim.Properties)
                        claim.Properties[kv.Key] = kv.Value;

                    identity.AddClaim(claim);
                }

            }

            return identity;
        }

        /// <summary>
        /// Decrypts a JWE and returns the clear text 
        /// </summary>
        /// <param name="jwtToken">the JWE that contains the cypher text.</param>
        /// <param name="validationParameters">contains crypto material.</param>
        /// <returns>the decoded / cleartext contents of the JWE.</returns>
        /// <exception cref="ArgumentNullException">if <paramref name="jwtToken"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="validationParameters"/>  is null.</exception>
        /// <exception cref="SecurityTokenException">if '<paramref name="jwtToken"/> .Enc' is null or empty.</exception>
        /// <exception cref="SecurityTokenDecompressionFailedException">if decompression failed.</exception>
        /// <exception cref="SecurityTokenEncryptionKeyNotFoundException">if '<paramref name="jwtToken"/> .Kid' is not null AND decryption fails.</exception>
        /// <exception cref="SecurityTokenDecryptionFailedException">if the JWE was not able to be decrypted.</exception>
        public string DecryptToken(JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (jwtToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (string.IsNullOrEmpty(jwtToken.Enc))
                throw LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TokenLogMessages.IDX10612)));

            var keys = GetContentEncryptionKeys(jwtToken, validationParameters);
            return JwtTokenUtilities.DecryptJwtToken(jwtToken, validationParameters, new JwtTokenDecryptionParameters
            {
                Alg = jwtToken.Alg,
                AuthenticationTag = jwtToken.AuthenticationTag,
                Ciphertext = jwtToken.Ciphertext,
                DecompressionFunction = JwtTokenUtilities.DecompressToken,
                Enc = jwtToken.Enc,
                EncodedHeader = jwtToken.EncodedHeader,
                EncodedToken = jwtToken.EncodedToken,
                InitializationVector = jwtToken.InitializationVector,
                Keys = keys,
                Zip = jwtToken.Zip,
            });
        }

        /// <summary>
        /// Encrypts a JWS.
        /// </summary>
        /// <param name="innerJwt">A 'JSON Web Token' (JWT) in JWS Compact Serialization Format.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the <paramref name="innerJwt"/>.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="innerJwt"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encryptingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentException">if both <see cref="EncryptingCredentials.CryptoProviderFactory"/> and <see cref="EncryptingCredentials.Key"/>.<see cref="CryptoProviderFactory"/> are null.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if the CryptoProviderFactory being used does not support the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if unable to create a token encryption provider for the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if encryption fails using the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if not using one of the supported content encryption key (CEK) algorithms: 128, 384 or 512 AesCbcHmac (this applies in the case of key wrap only, not direct encryption).</exception>
        public string EncryptToken(string innerJwt, EncryptingCredentials encryptingCredentials)
        {
            if (string.IsNullOrEmpty(innerJwt))
                throw LogHelper.LogArgumentNullException(nameof(innerJwt));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            return EncryptTokenPrivate(innerJwt, encryptingCredentials, null, null, null);
        }

        /// <summary>
        /// Encrypts a JWS.
        /// </summary>
        /// <param name="innerJwt">A 'JSON Web Token' (JWT) in JWS Compact Serialization Format.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the <paramref name="innerJwt"/>.</param>
        /// <param name="additionalHeaderClaims">Defines the dictionary containing any custom header claims that need to be added to the outer JWT token header.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="innerJwt"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encryptingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="additionalHeaderClaims"/> is null.</exception>
        /// <exception cref="ArgumentException">if both <see cref="EncryptingCredentials.CryptoProviderFactory"/> and <see cref="EncryptingCredentials.Key"/>.<see cref="CryptoProviderFactory"/> are null.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if the CryptoProviderFactory being used does not support the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if unable to create a token encryption provider for the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if encryption fails using the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if not using one of the supported content encryption key (CEK) algorithms: 128, 384 or 512 AesCbcHmac (this applies in the case of key wrap only, not direct encryption).</exception>
        public string EncryptToken(string innerJwt, EncryptingCredentials encryptingCredentials, IDictionary<string, object> additionalHeaderClaims)
        {
            if (string.IsNullOrEmpty(innerJwt))
                throw LogHelper.LogArgumentNullException(nameof(innerJwt));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            if (additionalHeaderClaims == null)
                throw LogHelper.LogArgumentNullException(nameof(additionalHeaderClaims));

            return EncryptTokenPrivate(innerJwt, encryptingCredentials, null, additionalHeaderClaims, null);
        }

        /// <summary>
        /// Encrypts a JWS.
        /// </summary>
        /// <param name="innerJwt">A 'JSON Web Token' (JWT) in JWS Compact Serialization Format.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the <paramref name="innerJwt"/>.</param>
        /// <param name="algorithm">Defines the compression algorithm that will be used to compress the 'innerJwt'.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="innerJwt"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encryptingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm"/> is null or empty.</exception>
        /// <exception cref="ArgumentException">if both <see cref="EncryptingCredentials.CryptoProviderFactory"/> and <see cref="EncryptingCredentials.Key"/>.<see cref="CryptoProviderFactory"/> are null.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if the CryptoProviderFactory being used does not support the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if unable to create a token encryption provider for the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenCompressionFailedException">if compression using <paramref name="algorithm"/> fails.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if encryption fails using the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if not using one of the supported content encryption key (CEK) algorithms: 128, 384 or 512 AesCbcHmac (this applies in the case of key wrap only, not direct encryption).</exception>
        public string EncryptToken(string innerJwt, EncryptingCredentials encryptingCredentials, string algorithm)
        {
            if (string.IsNullOrEmpty(innerJwt))
                throw LogHelper.LogArgumentNullException(nameof(innerJwt));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            return EncryptTokenPrivate(innerJwt, encryptingCredentials, algorithm, null, null);
        }

        /// <summary>
        /// Encrypts a JWS.
        /// </summary>
        /// <param name="innerJwt">A 'JSON Web Token' (JWT) in JWS Compact Serialization Format.</param>
        /// <param name="encryptingCredentials">Defines the security key and algorithm that will be used to encrypt the <paramref name="innerJwt"/>.</param>
        /// <param name="algorithm">Defines the compression algorithm that will be used to compress the 'innerJwt'.</param>
        /// <param name="additionalHeaderClaims">Defines the dictionary containing any custom header claims that need to be added to the outer JWT token header.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="innerJwt"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="encryptingCredentials"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="additionalHeaderClaims"/> is null or empty.</exception>
        /// <exception cref="ArgumentException">if both <see cref="EncryptingCredentials.CryptoProviderFactory"/> and <see cref="EncryptingCredentials.Key"/>.<see cref="CryptoProviderFactory"/> are null.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if the CryptoProviderFactory being used does not support the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if unable to create a token encryption provider for the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenCompressionFailedException">if compression using 'algorithm' fails.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if encryption fails using the <see cref="EncryptingCredentials.Enc"/> (algorithm), <see cref="EncryptingCredentials.Key"/> pair.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">if not using one of the supported content encryption key (CEK) algorithms: 128, 384 or 512 AesCbcHmac (this applies in the case of key wrap only, not direct encryption).</exception>
        public string EncryptToken(string innerJwt, EncryptingCredentials encryptingCredentials, string algorithm, IDictionary<string, object> additionalHeaderClaims)
        {
            if (string.IsNullOrEmpty(innerJwt))
                throw LogHelper.LogArgumentNullException(nameof(innerJwt));

            if (encryptingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(encryptingCredentials));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (additionalHeaderClaims == null)
                throw LogHelper.LogArgumentNullException(nameof(additionalHeaderClaims));

            return EncryptTokenPrivate(innerJwt, encryptingCredentials, algorithm, additionalHeaderClaims, null);
        }

        private static string EncryptTokenPrivate(string innerJwt, EncryptingCredentials encryptingCredentials, string compressionAlgorithm, IDictionary<string, object> additionalHeaderClaims, string tokenType)
        {
            var cryptoProviderFactory = encryptingCredentials.CryptoProviderFactory ?? encryptingCredentials.Key.CryptoProviderFactory;

            if (cryptoProviderFactory == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(TokenLogMessages.IDX10620));

            byte[] wrappedKey = null;
            SecurityKey securityKey = JwtTokenUtilities.GetSecurityKey(encryptingCredentials, cryptoProviderFactory, out wrappedKey);

            using (var encryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(securityKey, encryptingCredentials.Enc))
            {
                if (encryptionProvider == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogMessages.IDX14103));

                var header = CreateDefaultJWEHeader(encryptingCredentials, compressionAlgorithm, tokenType);

                if (additionalHeaderClaims != null)
                    header.Merge(JObject.FromObject(additionalHeaderClaims));

                byte[] plainText;
                if (!string.IsNullOrEmpty(compressionAlgorithm))
                {
                    try
                    {
                        plainText = CompressToken(innerJwt, compressionAlgorithm);
                    }
                    catch (Exception ex)
                    {
                        throw LogHelper.LogExceptionMessage(new SecurityTokenCompressionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10680, compressionAlgorithm), ex));
                    }
                }
                else
                {
                    plainText = Encoding.UTF8.GetBytes(innerJwt);
                }

                try
                {
                    var rawHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header.ToString(Formatting.None)));
                    var encryptionResult = encryptionProvider.Encrypt(plainText, Encoding.ASCII.GetBytes(rawHeader));
                    return JwtConstants.DirectKeyUseAlg.Equals(encryptingCredentials.Alg, StringComparison.Ordinal) ?
                        string.Join(".", rawHeader, string.Empty, Base64UrlEncoder.Encode(encryptionResult.IV), Base64UrlEncoder.Encode(encryptionResult.Ciphertext), Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag)):
                        string.Join(".", rawHeader, Base64UrlEncoder.Encode(wrappedKey), Base64UrlEncoder.Encode(encryptionResult.IV), Base64UrlEncoder.Encode(encryptionResult.Ciphertext), Base64UrlEncoder.Encode(encryptionResult.AuthenticationTag));
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10616, encryptingCredentials.Enc, encryptingCredentials.Key), ex));
                }
            }
        }

        internal IEnumerable<SecurityKey> GetContentEncryptionKeys(JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            IEnumerable<SecurityKey> keys = null;

            if (validationParameters.TokenDecryptionKeyResolver != null)
                keys = validationParameters.TokenDecryptionKeyResolver(jwtToken.EncodedToken, jwtToken, jwtToken.Kid, validationParameters);
            else
            {
                var key = ResolveTokenDecryptionKey(jwtToken.EncodedToken, jwtToken, validationParameters);
                if (key != null)
                    keys = new List<SecurityKey> { key };
            }

            // control gets here if:
            // 1. User specified delegate: TokenDecryptionKeyResolver returned null
            // 2. ResolveTokenDecryptionKey returned null
            // Try all the keys. This is the degenerate case, not concerned about perf.
            if (keys == null)
                keys = JwtTokenUtilities.GetAllDecryptionKeys(validationParameters);

            if (jwtToken.Alg.Equals(JwtConstants.DirectKeyUseAlg, StringComparison.Ordinal))
                return keys;

            var unwrappedKeys = new List<SecurityKey>();
            // keep track of exceptions thrown, keys that were tried
            var exceptionStrings = new StringBuilder();
            var keysAttempted = new StringBuilder();
            foreach (var key in keys)
            {
                try
                {
                    if (key.CryptoProviderFactory.IsSupportedAlgorithm(jwtToken.Alg, key))
                    {
                        var kwp = key.CryptoProviderFactory.CreateKeyWrapProviderForUnwrap(key, jwtToken.Alg);
                        var unwrappedKey = kwp.UnwrapKey(Base64UrlEncoder.DecodeBytes(jwtToken.EncryptedKey));
                        unwrappedKeys.Add(new SymmetricSecurityKey(unwrappedKey));
                    }
                }
                catch (Exception ex)
                {
                    exceptionStrings.AppendLine(ex.ToString());
                }
                keysAttempted.AppendLine(key.ToString());
            }

            if (unwrappedKeys.Count > 0 || exceptionStrings.Length == 0)
                return unwrappedKeys;
            else
                throw LogHelper.LogExceptionMessage(new SecurityTokenKeyWrapException(LogHelper.FormatInvariant(TokenLogMessages.IDX10618, keysAttempted, exceptionStrings, jwtToken)));
        }

        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use when decrypting a JWE.
        /// </summary>
        /// <param name="token">The <see cref="string"/> the token that is being decrypted.</param>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> that is being decrypted.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/>  required for validation.</param>
        /// <returns>Returns a <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <remarks>If key fails to resolve, then null is returned</remarks>
        protected virtual SecurityKey ResolveTokenDecryptionKey(string token, JsonWebToken jwtToken, TokenValidationParameters validationParameters)
        {
            if (jwtToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (!string.IsNullOrEmpty(jwtToken.Kid))
            {
                if (validationParameters.TokenDecryptionKey != null
                    && string.Equals(validationParameters.TokenDecryptionKey.KeyId, jwtToken.Kid, validationParameters.TokenDecryptionKey is X509SecurityKey ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                    return validationParameters.TokenDecryptionKey;

                if (validationParameters.TokenDecryptionKeys != null)
                {
                    foreach (var key in validationParameters.TokenDecryptionKeys)
                    {
                        if (key != null && string.Equals(key.KeyId, jwtToken.Kid, key is X509SecurityKey ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                            return key;
                    }
                }
            }

            if (!string.IsNullOrEmpty(jwtToken.X5t))
            {
                if (validationParameters.TokenDecryptionKey != null)
                {
                    if (string.Equals(validationParameters.TokenDecryptionKey.KeyId, jwtToken.X5t, validationParameters.TokenDecryptionKey is X509SecurityKey ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                        return validationParameters.TokenDecryptionKey;

                    var x509Key = validationParameters.TokenDecryptionKey as X509SecurityKey;
                    if (x509Key != null && string.Equals(x509Key.X5t, jwtToken.X5t, StringComparison.OrdinalIgnoreCase))
                        return validationParameters.TokenDecryptionKey;
                }

                if (validationParameters.TokenDecryptionKeys != null)
                {
                    foreach (var key in validationParameters.TokenDecryptionKeys)
                    {
                        if (key != null && string.Equals(key.KeyId, jwtToken.X5t, key is X509SecurityKey ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                            return key;

                        var x509Key = key as X509SecurityKey;
                        if (x509Key != null && string.Equals(x509Key.X5t, jwtToken.X5t, StringComparison.OrdinalIgnoreCase))
                            return key;
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Converts a string into an instance of <see cref="JsonWebToken"/>.
        /// </summary>
        /// <param name="token">A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format.</param>
        /// <returns>A <see cref="JsonWebToken"/></returns>
        /// <exception cref="ArgumentNullException">'token' is null or empty.</exception>
        /// <exception cref="ArgumentException">'token.Length' is greater than <see cref="TokenHandler.MaximumTokenSizeInBytes"/>.</exception>
        /// <remarks><para>If the 'token' is in JWE Compact Serialization format, only the protected header will be deserialized.</para>
        /// This method is unable to decrypt the payload. Use <see cref="ValidateToken(string, TokenValidationParameters)"/>to obtain the payload.</remarks>
        public virtual JsonWebToken ReadJsonWebToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (token.Length > MaximumTokenSizeInBytes)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes)));

            return new JsonWebToken(token);
        }

        /// <summary>
        /// Converts a string into an instance of <see cref="JsonWebToken"/>.
        /// </summary>
        /// <param name="token">A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format.</param>
        /// <returns>A <see cref="JsonWebToken"/></returns>
        /// <exception cref="ArgumentNullException">'token' is null or empty.</exception>
        /// <exception cref="ArgumentException">'token.Length' is greater than <see cref="TokenHandler.MaximumTokenSizeInBytes"/>.</exception>
        public virtual SecurityToken ReadToken(string token)
        {
            return ReadJsonWebToken(token);
        }

        /// <summary>
        /// Validates a JWS or a JWE.
        /// </summary>
        /// <param name="token">A 'JSON Web Token' (JWT) in JWS or JWE Compact Serialization Format.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/>  required for validation.</param>
        /// <returns>A <see cref="TokenValidationResult"/></returns>
        public virtual TokenValidationResult ValidateToken(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrEmpty(token))
                return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(token)), IsValid = false };

            if (validationParameters == null)
                return new TokenValidationResult { Exception = LogHelper.LogArgumentNullException(nameof(validationParameters)), IsValid = false };

            if (token.Length > MaximumTokenSizeInBytes)
                return new TokenValidationResult { Exception = LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(TokenLogMessages.IDX10209, token.Length, MaximumTokenSizeInBytes))), IsValid = false };

            var tokenParts = token.Split(new char[] { '.' }, JwtConstants.MaxJwtSegmentCount + 1);
            if (tokenParts.Length != JwtConstants.JwsSegmentCount && tokenParts.Length != JwtConstants.JweSegmentCount)
                return new TokenValidationResult { Exception = LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14111, token))), IsValid = false };

            var validationParametersCopy = validationParameters;
            if (validationParameters.ConfigurationManager != null)
            {
                try
                {
                    var configuration = validationParametersCopy.ConfigurationManager.GetBaseConfigurationAsync(CancellationToken.None).GetAwaiter().GetResult();
                    validationParametersCopy = validationParameters.Clone();
                    validationParametersCopy.Configuration = configuration;
                }
                catch (Exception ex)
                {
                    // If either a signing key or a valid issuer was not provided through the TVP, we want to stop processing on configuration retrieval failure.
                    // Otherwise, we should keep going with validation.
                    if ((validationParametersCopy.ValidateIssuer && string.IsNullOrWhiteSpace(validationParametersCopy.ValidIssuer) && (validationParametersCopy.ValidIssuers == null || !validationParametersCopy.ValidIssuers.Any()) && validationParametersCopy.IssuerValidator == null
                        && validationParametersCopy.TokenDecryptionKey == null && (validationParametersCopy.TokenDecryptionKeys == null || !validationParametersCopy.TokenDecryptionKeys.Any()) && validationParametersCopy.TokenDecryptionKeyResolver == null)
                        || (validationParametersCopy.RequireSignedTokens && validationParametersCopy.IssuerSigningKey == null && (validationParametersCopy.IssuerSigningKeys == null || !validationParametersCopy.IssuerSigningKeys.Any()) && validationParametersCopy.IssuerSigningKeyResolver == null))
                    {
                        return new TokenValidationResult
                        {
                            Exception = ex,
                            IsValid = false
                        };
                    }

                    LogHelper.LogInformation(LogHelper.FormatInvariant(TokenLogMessages.IDX10261, validationParametersCopy.ConfigurationManager.MetadataAddress));
                }
            }

            try
            {
                if (tokenParts.Length == JwtConstants.JweSegmentCount)
                {
                    var jwtToken = new JsonWebToken(token);
                    var decryptedJwt = DecryptToken(jwtToken, validationParametersCopy);
                    var innerToken = ValidateSignature(decryptedJwt, validationParametersCopy);
                    jwtToken.InnerToken = innerToken;
                    var innerTokenValidationResult = ValidateTokenPayload(innerToken, validationParametersCopy);
                    return new TokenValidationResult
                    {
                        SecurityToken = jwtToken,
                        ClaimsIdentity = innerTokenValidationResult.ClaimsIdentity,
                        IsValid = true,
                        TokenType = innerTokenValidationResult.TokenType
                    };
                }
                else
                {
                    var jsonWebToken = ValidateSignature(token, validationParametersCopy);
                    return ValidateTokenPayload(jsonWebToken, validationParametersCopy);
                }
            }
            catch (Exception ex)
            {
                return new TokenValidationResult
                {
                    Exception = ex,
                    IsValid = false
                };
            }
        }

        private TokenValidationResult ValidateTokenPayload(JsonWebToken jsonWebToken, TokenValidationParameters validationParameters)
        {
            var expires = jsonWebToken.TryGetClaim(JwtRegisteredClaimNames.Exp, out var _) ? (DateTime?)jsonWebToken.ValidTo : null;
            var notBefore = jsonWebToken.TryGetClaim(JwtRegisteredClaimNames.Nbf, out var _) ? (DateTime?)jsonWebToken.ValidFrom : null;

            Validators.ValidateLifetime(notBefore, expires, jsonWebToken, validationParameters);
            Validators.ValidateAudience(jsonWebToken.Audiences, jsonWebToken, validationParameters);
            var issuer = Validators.ValidateIssuer(jsonWebToken.Issuer, jsonWebToken, validationParameters);
            Validators.ValidateTokenReplay(expires, jsonWebToken.EncodedToken, validationParameters);
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                ValidateToken(jsonWebToken.Actor, validationParameters.ActorValidationParameters ?? validationParameters);
            }
            Validators.ValidateIssuerSecurityKey(jsonWebToken.SigningKey, jsonWebToken, validationParameters);
            var type = Validators.ValidateTokenType(jsonWebToken.Typ, jsonWebToken, validationParameters);

            return new TokenValidationResult
            {
                SecurityToken = jsonWebToken,
                ClaimsIdentity = CreateClaimsIdentity(jsonWebToken, validationParameters, issuer),
                IsValid = true,
                TokenType = type
            };
        }

        /// <summary>
        /// Validates the JWT signature.
        /// </summary>
        private static JsonWebToken ValidateSignature(string token, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(token))
                throw LogHelper.LogArgumentNullException(nameof(token));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.SignatureValidator != null)
            {
                var validatedToken = validationParameters.SignatureValidator(token, validationParameters);
                if (validatedToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10505, token)));

                var validatedJsonWebToken = validatedToken as JsonWebToken;
                if (validatedJsonWebToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10506, typeof(JsonWebToken), validatedToken.GetType(), token)));

                return validatedJsonWebToken;
            }

            JsonWebToken jwtToken = null;

            if (validationParameters.TokenReader != null)
            {
                var securityToken = validationParameters.TokenReader(token, validationParameters);
                if (securityToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10510, token)));

                jwtToken = securityToken as JsonWebToken;
                if (jwtToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10509, typeof(JsonWebToken), securityToken.GetType(), token)));
            }
            else
            {
                jwtToken = new JsonWebToken(token);
            }

            var encodedBytes = Encoding.UTF8.GetBytes(jwtToken.EncodedHeader + "." + jwtToken.EncodedPayload);
            if (string.IsNullOrEmpty(jwtToken.EncodedSignature))
            {
                if (validationParameters.RequireSignedTokens)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10504, token)));
                else
                    return jwtToken;
            }

            bool kidMatched = false;
            IEnumerable<SecurityKey> keys = null;
            if (validationParameters.IssuerSigningKeyResolver != null)
            {
                keys = validationParameters.IssuerSigningKeyResolver(token, jwtToken, jwtToken.Kid, validationParameters);
            }
            else
            {
                var key = JwtTokenUtilities.ResolveTokenSigningKey(jwtToken.Kid, jwtToken.X5t, validationParameters);
                if (key != null)
                {
                    kidMatched = true;
                    keys = new List<SecurityKey> { key };
                }
            }

            if (keys == null && validationParameters.TryAllIssuerSigningKeys)
            {
                // control gets here if:
                // 1. User specified delegate: IssuerSigningKeyResolver returned null
                // 2. ResolveIssuerSigningKey returned null
                // Try all the keys. This is the degenerate case, not concerned about perf.
                keys = TokenUtilities.GetAllSigningKeys(validationParameters);
            }

            // keep track of exceptions thrown, keys that were tried
            var exceptionStrings = new StringBuilder();
            var keysAttempted = new StringBuilder();
            var kidExists = !string.IsNullOrEmpty(jwtToken.Kid);
            byte[] signatureBytes;

            try
            {
                signatureBytes = Base64UrlEncoder.DecodeBytes(jwtToken.EncodedSignature);
            }
            catch (FormatException e)
            {
                throw new SecurityTokenInvalidSignatureException(TokenLogMessages.IDX10508, e);
            }

            if (keys != null)
            {
                foreach (var key in keys)
                {
                    try
                    {
                        if (ValidateSignature(encodedBytes, signatureBytes, key, jwtToken.Alg, jwtToken, validationParameters))
                        {
                            LogHelper.LogInformation(TokenLogMessages.IDX10242, token);
                            jwtToken.SigningKey = key;
                            return jwtToken;
                        }
                    }
                    catch (Exception ex)
                    {
                        exceptionStrings.AppendLine(ex.ToString());
                    }

                    if (key != null)
                    {
                        keysAttempted.AppendLine(key.ToString() + " , KeyId: " + key.KeyId);
                        if (kidExists && !kidMatched && key.KeyId != null)
                            kidMatched = jwtToken.Kid.Equals(key.KeyId, key is X509SecurityKey ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
                    }
                }

            }

            if (kidExists)
            {
                if (kidMatched)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10511, keysAttempted, jwtToken.Kid, exceptionStrings, jwtToken)));

                var expires = jwtToken.TryGetClaim(JwtRegisteredClaimNames.Exp, out var _) ? (DateTime?)jwtToken.ValidTo : null;
                var notBefore = jwtToken.TryGetClaim(JwtRegisteredClaimNames.Nbf, out var _) ? (DateTime?)jwtToken.ValidFrom : null;

                InternalValidators.ValidateLifetimeAndIssuerAfterSignatureNotValidatedJwt(
                    jwtToken,
                    notBefore,
                    expires,
                    jwtToken.Kid,
                    validationParameters,
                    exceptionStrings);
            }

            if (keysAttempted.Length > 0)
                throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(LogHelper.FormatInvariant(TokenLogMessages.IDX10503, keysAttempted, exceptionStrings, jwtToken)));

            throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(TokenLogMessages.IDX10500));
        }

        /// <summary>
        /// Obtains a <see cref="SignatureProvider "/> and validates the signature.
        /// </summary>
        /// <param name="encodedBytes">Bytes to validate.</param>
        /// <param name="signature">Signature to compare against.</param>
        /// <param name="key"><See cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">Crypto algorithm to use.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters">Priority will be given to <see cref="TokenValidationParameters.CryptoProviderFactory"/> over <see cref="SecurityKey.CryptoProviderFactory"/>.</param>
        /// <returns>'true' if signature is valid.</returns>
        internal static bool ValidateSignature(byte[] encodedBytes, byte[] signature, SecurityKey key, string algorithm, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            var cryptoProviderFactory = validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory;
            if (!cryptoProviderFactory.IsSupportedAlgorithm(algorithm, key))
            {
                LogHelper.LogInformation(LogMessages.IDX14000, algorithm, key);
                return false;
            }

            Validators.ValidateAlgorithm(algorithm, key, securityToken, validationParameters);

            var signatureProvider = cryptoProviderFactory.CreateForVerifying(key, algorithm);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(TokenLogMessages.IDX10636, key == null ? "Null" : key.ToString(), algorithm ?? "Null")));

            try
            {
                return signatureProvider.Verify(encodedBytes, signature);
            }
            finally
            {
                cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }
    }
}
