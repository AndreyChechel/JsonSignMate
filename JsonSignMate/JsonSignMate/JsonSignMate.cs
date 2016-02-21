/*
Copyright 2016 Andrey Chechel

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using devSane.Json.Internal;
using Newtonsoft.Json;

namespace devSane.Json
{
    public class JsonSignMate
    {
        public static readonly JsonSignMateFactory Factory = new JsonSignMateFactory();

        private readonly JsonSignMateConfig _config;

        internal JsonSignMate(JsonSignMateConfig config)
        {
            _config = config;
        }

        #region Public methods

        public string Sign(string json)
        {
            var jsonBytes = Encoding.Unicode.GetBytes(json);
            var signature = _config.Method.ComputeSignature(jsonBytes);
            var signatureNode = new Dictionary<string, object> { { _config.SignatureKey, signature } };

            var updatedJson = JsonProcessor.AppendNodes(json, signatureNode);
            return updatedJson;
        }

        public bool Validate(string json)
        {
            var storedSignature = ReadSignature(json);
            if (storedSignature == null)
            {
                return false;
            }

            var jsonWithoutSignature = RemoveSignature(json);
            var jsonWithoutSignatureBytes = Encoding.Unicode.GetBytes(jsonWithoutSignature);

            var calculatedSignature = _config.Method.ComputeSignature(jsonWithoutSignatureBytes);

            return string.Equals(storedSignature, calculatedSignature, StringComparison.Ordinal);
        }

        public string RemoveSignature(string json)
        {
            var updatedJson = JsonProcessor.RemoveRootObjProperties(json, _config.SignatureKey);
            return updatedJson;
        }

        #endregion

        #region Private methods

        private string ReadSignature(string jsonStr)
        {
            var values = JsonProcessor.ReadRootObjProperty(jsonStr, _config.SignatureKey, JsonToken.String);
            if (values == null || !values.Any())
            {
                return null;
            }

            if (values.Length > 1)
            {
                throw new InvalidOperationException("Duplicated Signature key.");
            }

            var str = values[0] as string;
            if (str == null)
            {
                throw new InvalidOperationException("Incorrect Signature type.");
            }

            return str;
        }

        #endregion
    }
}
