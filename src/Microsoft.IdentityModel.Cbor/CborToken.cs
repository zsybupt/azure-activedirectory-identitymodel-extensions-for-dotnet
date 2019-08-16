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
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.CborTokens
{
    /// <summary>
    /// A <see cref="SecurityToken"/> designed for representing a Concise Binary Object Representation Token (CBOR). 
    /// </summary>
    public class CborToken : SecurityToken
    {
        /// <summary>
        /// Initializes a new instance of <see cref="CborToken"/> from a string in JWS or JWE Compact serialized format.
        /// </summary>
        public CborToken()
        {
        }

        /// <summary>
        /// 
        /// </summary>
        public override string Id => throw new NotImplementedException();

        /// <summary>
        /// 
        /// </summary>
        public override string Issuer => throw new NotImplementedException();

        /// <summary>
        /// 
        /// </summary>
        public override SecurityKey SecurityKey => throw new NotImplementedException();

        /// <summary>
        /// 
        /// </summary>
        public override SecurityKey SigningKey { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        /// <summary>
        /// 
        /// </summary>
        public override DateTime ValidFrom => throw new NotImplementedException();

        /// <summary>
        /// 
        /// </summary>
        public override DateTime ValidTo => throw new NotImplementedException();
    }
}
