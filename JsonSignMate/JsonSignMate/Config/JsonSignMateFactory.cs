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

using System.Security;
using System.Security.Cryptography;
using devSane.Json.Internal;

namespace devSane.Json
{
    public class JsonSignMateFactory
    {
        internal JsonSignMateFactory()
        {
        }

        public JsonSignMate CreateRS(JsonSignAlgorithmRS algorithm, RSAParameters rsaParameters)
        {
            var method = new JsonSignMethodRS(algorithm, rsaParameters);
            var config = new JsonSignMateConfig { Method = method };
            return new JsonSignMate(config);
        }

        public JsonSignMate CreateRS(JsonSignAlgorithmRS algorithm, byte[] rsaParametersBytes)
        {
            var rsaParameters = JsonProcessor.Deserialize<RSAParameters>(rsaParametersBytes);
            return CreateRS(algorithm, rsaParameters);

        }

        public JsonSignMate CreateRS(JsonSignAlgorithmRS algorithm)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                return CreateRS(algorithm, rsa.ExportParameters(true));
            }
        }

        public JsonSignMate CreateHS(JsonSignAlgorithmHS algorithm, SecureString secret)
        {
            var method = new JsonSignMethodHS(algorithm, secret);
            var config = new JsonSignMateConfig { Method = method };
            return new JsonSignMate(config);
        }

        public JsonSignMate CreateES(JsonSignAlgorithmES algorithm, CngKey key)
        {
            var method = new JsonSignMethodES(algorithm, key);
            var config = new JsonSignMateConfig { Method = method };
            return new JsonSignMate(config);
        }

        public JsonSignMate CreateES(JsonSignAlgorithmES algorithm, byte[] keyBytes)
        {
            using (var key = CngKey.Import(keyBytes, CngKeyBlobFormat.EccPrivateBlob))
            {
                return CreateES(algorithm, key);
            }
        }

        public JsonSignMate CreateES(JsonSignAlgorithmES algorithm)
        {
            using (var es = new ECDsaCng())
            {
                return CreateES(algorithm, es.Key);
            }
        }
    }
}