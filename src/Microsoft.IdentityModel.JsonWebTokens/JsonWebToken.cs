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
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
#if !NET45
using System.Text.Json;
#endif
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a JSON Web Token (JWT). 
    /// </summary>
    public class JsonWebToken : SecurityToken, IClaimProvider
    {
        internal bool HasSignature { get; set; }
        private char[] _hChars;
        private byte[] _messageBytes;
        private char[] _pChars;
        private  byte[] _signatureBytes;
        private char[] _sChars;

        private Lazy<string> _act;
        private Lazy<string> _alg;
        private Lazy<IEnumerable<string>> _audiences;
        private Lazy<string> _cty;
        private Lazy<string> _enc;
        private Lazy<string> _encodedHeader;
        private Lazy<string> _encodedPayload;
        private Lazy<string> _encodedSignature;
        private Lazy<DateTime> _iat;
        private Lazy<string> _id;
        private Lazy<string> _iss;
        private Lazy<string> _kid;
        private Lazy<string> _sub;
        private Lazy<string> _typ;
        private Lazy<DateTime> _validFrom;
        private Lazy<DateTime> _validTo;
        private Lazy<string> _x5t;
        private Lazy<string> _zip;
        internal byte[] _ciphertextBytes;
        internal byte[] _initializationVectorBytes;
        internal byte[] _authenticationTagBytes;
        internal byte[] _encodedHeaderAsciiBytes;
        internal byte[] _encryptedKeyBytes;

        /// <summary>
        /// Initializes a new instance of <see cref="JsonWebToken"/> from a string in JWS or JWE Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A JSON Web Token that has been serialized in JWS or JWE Compact serialized format.</param>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null or empty.</exception>
        /// <exception cref="ArgumentException">'jwtEncodedString' is not in JWS or JWE Compact serialization format.</exception>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7519 (JWT)
        /// see: https://datatracker.ietf.org/doc/html/rfc7515 (JWS)
        /// see: https://datatracker.ietf.org/doc/html/rfc7516 (JWE)
        /// <para>
        /// The contents of the returned <see cref="JsonWebToken"/> have not been validated, the JSON Web Token is simply decoded. Validation can be accomplished using the validation methods in <see cref="JsonWebTokenHandler"/>
        /// </para>
        /// </remarks>
        public JsonWebToken(string jwtEncodedString)
        {
            if (string.IsNullOrEmpty(jwtEncodedString))
                throw new ArgumentNullException(nameof(jwtEncodedString));

            Initialize();
            ReadToken(jwtEncodedString);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonWebToken"/> class where the header contains the crypto algorithms applied to the encoded header and payload.
        /// </summary>
        /// <param name="header">A string containing JSON which represents the cryptographic operations applied to the JWT and optionally any additional properties of the JWT.</param>
        /// <param name="payload">A string containing JSON which represents the claims contained in the JWT. Each claim is a JSON object of the form { Name, Value }.</param>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7519 (JWT)
        /// see: https://datatracker.ietf.org/doc/html/rfc7515 (JWS)
        /// see: https://datatracker.ietf.org/doc/html/rfc7516 (JWE)
        /// <para>
        /// The contents of the returned <see cref="JsonWebToken"/> have not been validated, the JSON Web Token is simply decoded. Validation can be accomplished using the validation methods in <see cref="JsonWebTokenHandler"/>
        /// </para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'header' is null.</exception>
        /// <exception cref="ArgumentNullException">'payload' is null.</exception>
        public JsonWebToken(string header, string payload)
        {
            if (string.IsNullOrEmpty(header))
                throw LogHelper.LogArgumentNullException(nameof(header));

            if (string.IsNullOrEmpty(payload))
                throw LogHelper.LogArgumentNullException(nameof(payload));

            try
            {
                HeaderClaimSet = new JsonClaimSet(header);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14301, header), ex));
            }

            try
            {
                PayloadClaimSet = new JsonClaimSet(payload);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14302, payload), ex));
            }

            Initialize();
        }

        private void Initialize()
        {
            _act = new Lazy<string>(ActorFactory);
            _alg = new Lazy<string>(AlgFactory);
            _audiences = new Lazy<IEnumerable<string>>(AudiencesFactory);
            _cty = new Lazy<string>(CtyFactory);
            _enc = new Lazy<string>(EncFactory);
            _encodedHeader = new Lazy<string>(EncodedHeaderFactory);
            _encodedPayload = new Lazy<string>(EncodedPayloadFactory);
            _encodedSignature = new Lazy<string>(EncodedSignatureFactory);
            _iat = new Lazy<DateTime>(IatFactory);
            _id = new Lazy<string>(IdFactory);
            _iss = new Lazy<string>(IssuerFactory);
            _kid = new Lazy<string>(KidFactory);
            _sub = new Lazy<string>(SubFactory);
            _typ = new Lazy<string>(TypFactory);
            _validTo = new Lazy<DateTime>(ValidToFactory);
            _validFrom = new Lazy<DateTime>(ValidFromFactory);
            _x5t = new Lazy<string>(X5tFactory);
            _zip = new Lazy<string>(ZipFactory);
        }

        /// <summary>
        /// Gets the 'value' of the 'actort' claim the payload.
        /// </summary>
        /// <remarks>
        /// If the 'actort' claim is not found, an empty string is returned.
        /// </remarks>
        public string Actor => _act.Value;

        private string ActorFactory()
        {
            return (InnerToken == null) ? PayloadClaimSet.GetStringValue(JwtRegisteredClaimNames.Actort) : InnerToken.PayloadClaimSet.GetStringValue(JwtRegisteredClaimNames.Actort);
        }

        /// <summary>
        /// Gets the 'value' of the 'alg' claim from the header.
        /// </summary>
        /// <remarks>
        /// Identifies the cryptographic algorithm used to encrypt or determine the value of the Content Encryption Key.
        /// Applicable to an encrypted JWT {JWE}.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1
        /// <para>
        /// If the 'alg' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Alg => _alg.Value;

        private string AlgFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Alg);
        }

        /// <summary>
        /// Gets the list of 'aud' claims from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the recipients that the JWT is intended for.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
        /// <para>
        /// If the 'aud' claim is not found, enumeration will be empty.
        /// </para>
        /// </remarks>
        public IEnumerable<string> Audiences => _audiences.Value;

        private IEnumerable<string> AudiencesFactory()
        {
#if NET45
            if (PayloadClaimSet.TryGetValue(JwtRegisteredClaimNames.Aud, out JToken value))
            {
                if (value.Type is JTokenType.String)
                    return new List<string> { value.ToObject<string>() };
                else if (value.Type is JTokenType.Array)
                    return value.ToObject<List<string>>();
            }
#else
            if (PayloadClaimSet.TryGetValue(JwtRegisteredClaimNames.Aud, out JsonElement audiences))
            {
                if (audiences.ValueKind == JsonValueKind.String)
                    return new List<string> { audiences.GetString() };

                if (audiences.ValueKind == JsonValueKind.Array)
                {
                    List<string> retVal = new List<string>();
                    foreach (JsonElement jsonElement in audiences.EnumerateArray())
                        retVal.Add(jsonElement.ToString());

                    return retVal;
                }
            }
#endif
            return Enumerable.Empty<string>();
        }

        /// <summary>
        /// Gets the AuthenticationTag from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// Contains the results of a Authentication Encryption with Associated Data (AEAD).
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-2
        /// <para>
        /// If this JWT is not encrypted with an algorithms that uses an Authentication Tag, an empty string will be returned.
        /// </para>
        /// </remarks>
        public string AuthenticationTag
        {
            // TODO - use lazy
            get
            {
                return _authenticationTagBytes == null ? string.Empty : UTF8Encoding.UTF8.GetString(_authenticationTagBytes);
            }
        }

        /// <summary>
        ///
        /// </summary>
        public byte[] AuthenticationTagBytes()
        {
            // TODO lazy
            return _authenticationTagBytes;
        }

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/> where each claim in the JWT { name, value } is returned as a <see cref="Claim"/>.
        /// </summary>
        /// <remarks>
        /// A <see cref="Claim"/> requires each value to be represented as a string. If the value was not a string, then <see cref="Claim.Type"/> contains the json type.
        /// <see cref="JsonClaimValueTypes"/> and <see cref="ClaimValueTypes"/> to determine the json type.
        /// </remarks>
        public virtual IEnumerable<Claim> Claims
        {
            get
            {
                if (InnerToken != null)
                    return InnerToken.Claims;

                return PayloadClaimSet.Claims(Issuer ?? ClaimsIdentity.DefaultIssuer);

            }
        }

        /// <summary>
        /// Gets a <see cref="IEnumerable{Claim}"/> where each claim in the JWT { name, value } is returned as a <see cref="Claim"/>.
        /// </summary>
        /// <remarks>
        /// A <see cref="Claim"/> requires each value to be represented as a string. If the value was not a string, then <see cref="Claim.Type"/> contains the json type.
        /// <see cref="JsonClaimValueTypes"/> and <see cref="ClaimValueTypes"/> to determine the json type.
        /// </remarks>
        public virtual IEnumerable<Claim> ActorClaims
        {
            get
            {
                if (InnerToken != null)
                    return InnerToken.Claims;

                return PayloadClaimSet.Claims(Issuer ?? ClaimsIdentity.DefaultIssuer);

            }
        }

        /// <summary>
        /// Gets the Ciphertext representing the encrypted JWT in the original raw data.
        /// </summary>
        /// <remarks>
        /// When decrypted using values in the JWE header will contain the plaintext payload.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-2
        /// <para>
        /// If this JWT is not encrypted, an empty string will be returned.
        /// </para>
        /// </remarks>
        public string Ciphertext
        {
            // TODO - use lazy
            get
            {
                return _ciphertextBytes == null ? string.Empty : UTF8Encoding.UTF8.GetString(_ciphertextBytes);
            }
        }

        /// <summary>
        ///
        /// </summary>
        public byte[] CipherBytes()
        {
            return _ciphertextBytes;
        }

        /// <summary>
        /// Gets the 'value' of the 'cty' claim from the header.
        /// </summary>
        /// <remarks>
        /// Used by JWS applications to declare the media type[IANA.MediaTypes] of the secured content (the payload).
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.12 (JWE)
        /// see: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10 (JWS)
        /// <para>
        /// If the 'cty' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Cty => _cty.Value;

        private string CtyFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Cty);
        }

        /// <summary>
        /// Gets the 'value' of the 'enc' claim from the header.
        /// </summary>
        /// <remarks>
        /// Identifies the content encryption algorithm used to perform authenticated encryption
        /// on the plaintext to produce the ciphertext and the Authentication Tag.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2
        /// </remarks>
        public string Enc => _enc.Value;

        private string EncFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Enc);
        }

        /// <summary>
        /// Gets the EncodedHeader from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded string of the JWT header.
        /// </remarks>
        public string EncodedHeader => _encodedHeader.Value;

        private string EncodedHeaderFactory()
        {
            return new string(_hChars);
        }

        /// <summary>
        /// Gets the EncodedPayload from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded of the JWT payload.
        /// </remarks>
        public string EncodedPayload => _encodedPayload.Value;

        private string EncodedPayloadFactory()
        {
            return new string(_pChars);
        }

        /// <summary>
        /// Gets the EncodedSignature from the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded of the JWT signature.
        /// If the JWT was not signed, an empty string is returned.
        /// </remarks>
        public string EncodedSignature => _encodedSignature.Value;

        private string EncodedSignatureFactory()
        {
            return new string(_sChars);
        }

        /// <summary>
        /// Gets the original raw data of this instance when it was created.
        /// </summary>
        /// <remarks>
        /// The original Base64UrlEncoded of the JWT.
        /// </remarks>
        public string EncodedToken { get; private set; }

        /// <summary>
        /// Gets the Encrypted Content Encryption Key.
        /// </summary>
        /// <remarks>
        /// For some algorithms this value may be null even though the JWT was encrypted.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-2
        /// <para>
        /// If not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string EncryptedKey { get; internal set; }

        internal bool HasPayloadClaim(string claimName)
        {
            return PayloadClaimSet.HasClaim(claimName);
        }

        /// <summary>
        /// Gets the 'value' of the 'jti' claim from the payload.
        /// </summary>
        /// <remarks>
        /// Provides a unique identifier for the JWT.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
        /// <para>
        /// If the 'jti' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public override string Id => _id.Value;

        private string IdFactory()
        {
            return PayloadClaimSet.GetStringValue(JwtRegisteredClaimNames.Jti);
        }

        /// <summary>
        /// Gets the Initialization Vector used when encrypting the plaintext.
        /// </summary>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1.4
        /// <para>
        /// Some algorithms may not use an Initialization Vector.
        /// If not found an empty string is returned.
        /// </para>
        /// </remarks>
        public string InitializationVector { get; internal set; }

        /// <summary>
        /// Gets the <see cref="JsonWebToken"/> associated with this instance.
        /// </summary>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-2
        /// For encrypted tokens {JWE}, this represents the JWT that was encrypted.
        /// <para>
        /// If the JWT is not encrypted, this value will be null.
        /// </para>
        /// </remarks>
        public JsonWebToken InnerToken { get; internal set; }

        /// <summary>
        /// Gets the 'value' of the 'iat' claim converted to a <see cref="DateTime"/> from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the time at which the JWT was issued.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
        /// <para>
        /// If the 'iat' claim is not found, then <see cref="DateTime.MinValue"/> is returned.
        /// </para>
        /// </remarks>
        public DateTime IssuedAt => _iat.Value;

        private DateTime IatFactory()
        {
            return PayloadClaimSet.GetDateTime(JwtRegisteredClaimNames.Iat);
        }

        /// <summary>
        /// Gets the 'value' of the 'iss' claim from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the principal that issued the JWT.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
        /// <para>
        /// If the 'iss' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public override string Issuer => _iss.Value;

        internal string IssuerFactory()
        {
            return PayloadClaimSet.GetStringValue(JwtRegisteredClaimNames.Iss);
        }

        /// <summary>
        /// Gets the 'value' of the 'kid' claim from the header.
        /// </summary>
        /// <remarks>
        /// 'kid'is a hint indicating which key was used to secure the JWS.
        /// see: https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4 (JWS)
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6 (JWE)
        /// <para>
        /// If the 'kid' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Kid => _kid.Value;

        private string KidFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Kid);
        }

        /// <summary>
        ///
        /// </summary>
        internal JsonClaimSet PayloadClaimSet { get; set; }

        /// <summary>
        ///
        /// </summary>
        internal JsonClaimSet HeaderClaimSet { get; set; }


        /// <summary>
        /// Not implemented.
        /// </summary>
        public override SecurityKey SecurityKey { get; }

        /// <summary>
        /// Gets or sets the <see cref="SecurityKey"/> that was used to sign this token.
        /// </summary>
        /// <remarks>
        /// If the JWT was not signed or validated, this value will be null.
        /// </remarks>
        public override SecurityKey SigningKey { get; set; }

        /// <summary>
        /// Gets the 'value' of the 'sub' claim from the payload.
        /// </summary>
        /// <remarks>
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
        /// Identifies the principal that is the subject of the JWT.
        /// <para>
        /// If the 'sub' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Subject => _sub.Value;

        private string SubFactory()
        {
            return PayloadClaimSet.GetStringValue(JwtRegisteredClaimNames.Sub);
        }

        /// <summary>
        /// Gets the 'value' of the 'typ' claim from the header.
        /// </summary>
        /// <remarks>
        /// Is used by JWT applications to declare the media type.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
        /// <para>
        /// If the 'typ' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Typ => _typ.Value;

        private string TypFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Typ);
        }

        /// <summary>
        /// Gets the 'value' of the 'x5t' claim from the header.
        /// </summary>
        /// <remarks>
        /// Is the base64url-encoded SHA-1 thumbprint(a.k.a.digest) of the DER encoding of the X.509 certificate used to sign this token.
        /// see : https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7
        /// <para>
        /// If the 'x5t' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string X5t => _x5t.Value;

        private string X5tFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.X5t);
        }

        /// <summary>
        /// Gets the 'value' of the 'nbf' claim converted to a <see cref="DateTime"/> from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the time before which the JWT MUST NOT be accepted for processing.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
        /// <para>
        /// If the 'nbf' claim is not found, then <see cref="DateTime.MinValue"/> is returned.
        /// </para>
        /// </remarks>
        public override DateTime ValidFrom => _validFrom.Value;

        internal DateTime ValidFromFactory()
        {
            return PayloadClaimSet.GetDateTime(JwtRegisteredClaimNames.Nbf);
        }

        /// <summary>
        /// Gets the 'value' of the 'exp' claim converted to a <see cref="DateTime"/> from the payload.
        /// </summary>
        /// <remarks>
        /// Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
        /// see: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
        /// <para>
        /// If the 'exp' claim is not found, then <see cref="DateTime.MinValue"/> is returned.
        /// </para>
        /// </remarks>
        public override DateTime ValidTo => _validTo.Value;

        internal DateTime ValidToFactory()
        {
            return PayloadClaimSet.GetDateTime(JwtRegisteredClaimNames.Exp);
        }

        /// <summary>
        /// Gets the 'value' of the 'zip' claim from the header.
        /// </summary>
        /// <remarks>
        /// The "zip" (compression algorithm) applied to the plaintext before encryption, if any.
        /// see: https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3
        /// <para>
        /// If the 'zip' claim is not found, an empty string is returned.
        /// </para>
        /// </remarks>
        public string Zip => _zip.Value;

        /// <summary>
        /// Gets a <see cref="Claim"/> representing the { key, 'value' } pair corresponding to the provided <paramref name="key"/>.
        /// </summary>
        /// <remarks>
        /// A <see cref="Claim"/> requires each value to be represented as a string. If the value was not a string, then <see cref="Claim.Type"/> contains the json type.
        /// <see cref="JsonClaimValueTypes"/> and <see cref="ClaimValueTypes"/> to determine the json type.
        /// <para>
        /// If the key has no corresponding value, this method will throw.
        /// </para>
        /// </remarks>
        public Claim GetClaim(string key)
        {
            return PayloadClaimSet.GetClaim(key, Issuer ?? ClaimsIdentity.DefaultIssuer);
        }

        /// <summary>
        /// Gets the 'value' corresponding to key from the JWT header transformed as type 'T'.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type are expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns>The value as <typeparamref name="T"/>.</returns>
        /// <exception cref="ArgumentException">if claim is not found or a transformation to <typeparamref name="T"/> cannot be made.</exception>
        public T GetHeaderValue<T>(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw LogHelper.LogArgumentNullException(nameof(key));

            return HeaderClaimSet.GetValue<T>(key);
        }

        /// <summary>
        /// Gets the 'value' corresponding to key from the JWT payload transformed as type 'T'.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type are expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns>The value as <typeparamref name="T"/>.</returns>
        /// <exception cref="ArgumentException">if claim is not found or a transformation to <typeparamref name="T"/> cannot be made.</exception>
        public T GetPayloadValue<T>(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (typeof(T).Equals(typeof(Claim)))
                return (T)(object)GetClaim(key);

            return PayloadClaimSet.GetValue<T>(key);
        }

        internal int NumberOfSegments { get; private set; }

        /// <summary>
        ///
        /// </summary>
#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] MessageBytes => _messageBytes;
#pragma warning restore CA1819 // Properties should not return arrays

        private void ReadToken(string encodedJson)
        {
            List<int> dots = new List<int>();
            int index = 0;
            while (index < encodedJson.Length && dots.Count <= JwtConstants.MaxJwtSegmentCount + 1)
            {
                if (encodedJson[index] == '.')
                    dots.Add(index);

                index++;
            }

            EncodedToken = encodedJson;
            if (dots.Count == JwtConstants.JwsSegmentCount - 1)
            {
                if (dots[1] + 1 == encodedJson.Length)
                {
                    HasSignature = false;
                    // TODO - have fixed value for this.
                    _signatureBytes = Base64UrlEncoder.UnsafeDecode(string.Empty.ToCharArray());
                }
                else
                {
                    HasSignature = true;
                    _sChars = encodedJson.ToCharArray(dots[1] + 1, encodedJson.Length - dots[1] - 1);
                    _signatureBytes = Base64UrlEncoder.UnsafeDecode(_sChars);
                }

                _hChars = encodedJson.ToCharArray(0, dots[0]);
                _pChars = encodedJson.ToCharArray(dots[0] + 1, dots[1] - dots[0] - 1);
                _messageBytes = Encoding.UTF8.GetBytes(encodedJson.ToCharArray(0, dots[1]));
                try
                {
                    HeaderClaimSet = new JsonClaimSet(Base64UrlEncoder.UnsafeDecode(_hChars));
                }
                catch(Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14102, encodedJson.Substring(0, dots[0]), encodedJson), ex));
                }

                try
                {
                    PayloadClaimSet = new JsonClaimSet(Base64UrlEncoder.UnsafeDecode(_pChars));
                }
                catch(Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14101, encodedJson.Substring(dots[0], dots[1] - dots[0]), encodedJson), ex));
                }
            }
            else if (dots.Count == JwtConstants.JweSegmentCount - 1)
            {
                char[] encodedHeader = encodedJson.ToCharArray(0, dots[0]);
                _encodedHeaderAsciiBytes = Encoding.ASCII.GetBytes(encodedHeader);
                _encryptedKeyBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[0] + 1, dots[1] - dots[0] - 1));
                _initializationVectorBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[1] + 1, dots[2] - dots[1] - 1));
                _ciphertextBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[2] + 1, dots[3] - dots[2] - 1));
                if (_ciphertextBytes.Length == 0)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX14306));

                _authenticationTagBytes = Base64UrlEncoder.UnsafeDecode(encodedJson.ToCharArray(dots[3] + 1, encodedJson.Length - dots[3] - 1));
                try
                {
                    HeaderClaimSet = new JsonClaimSet(Base64UrlEncoder.UnsafeDecode(encodedHeader));
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14102, encodedJson.Substring(0, dots[0]), encodedJson), ex));
                }
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14100, encodedJson)));
            }

            NumberOfSegments = dots.Count + 1;
        }

        /// <summary>
        ///
        /// </summary>
#pragma warning disable CA1819 // Properties should not return arrays
        public byte[] SignatureBytes => _signatureBytes;
#pragma warning restore CA1819 // Properties should not return arrays

        /// <summary>
        /// Try to get a <see cref="Claim"/> representing the { key, 'value' } pair corresponding to the provided <paramref name="key"/>.
        /// </summary>
        /// <remarks>
        /// A <see cref="Claim"/> requires each value to be represented as a string. If the value was not a string, then <see cref="Claim.Type"/> contains the json type.
        /// <see cref="JsonClaimValueTypes"/> and <see cref="ClaimValueTypes"/> to determine the json type.
        /// </remarks>
        /// <returns>true if successful, false otherwise.</returns>
        public bool TryGetClaim(string key, out Claim value)
        {
            return PayloadClaimSet.TryGetClaim(key, Issuer ?? ClaimsIdentity.DefaultIssuer, out value);
        }

        /// <summary>
        /// Try to get the 'value' corresponding to key from the JWT payload transformed as type 'T'.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type are expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns>true if successful, false otherwise.</returns>
        public bool TryGetPayloadValue<T>(string key, out T value)
        {
            if (string.IsNullOrEmpty(key))
            {
                value = default(T);
                return false;
            }

            if (typeof(T).Equals(typeof(Claim)))
            {
                var foundClaim = TryGetClaim(key, out var claim);
                value = (T)(object)claim;
                return foundClaim;
            }

            return PayloadClaimSet.TryGetValue<T>(key, out value);
        }


        /// <summary>
        /// Try to get the 'value' corresponding to key from the JWT header transformed as type 'T'.
        /// </summary>
        /// <remarks>
        /// The expectation is that the 'value' corresponds to a type are expected in a JWT token.
        /// The 5 basic types: number, string, true / false, nil, array (of basic types).
        /// This is not a general purpose translation layer for complex types.
        /// </remarks>
        /// <returns>true if successful, false otherwise.</returns>
        public bool TryGetHeaderValue<T>(string key, out T value)
        {
            if (string.IsNullOrEmpty(key))
            {
                value = default;
                return false;
            }

            return HeaderClaimSet.TryGetValue<T>(key, out value);
        }

        #region Factories for Lazy

        private string ZipFactory()
        {
            return HeaderClaimSet.GetStringValue(JwtHeaderParameterNames.Zip);
        }

        #endregion
    }
}
