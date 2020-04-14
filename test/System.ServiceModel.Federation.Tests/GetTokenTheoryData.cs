// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Xml;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;

namespace System.ServiceModel.Federation.Tests
{
    public class GetTokenTheoryData: TheoryDataBase
    {
        public SecurityToken SecurityToken { get; set; }
        public XmlElement ExpectedXml { get; set; }
    }
}
