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
using System.Security;
using System.Security.Cryptography;
using devSane.Json.Internal;

namespace devSane.Json.Config
{
    public abstract class JsonSignatureMethod : IDisposable, ICloneable
    {
        #region Properties

        protected bool IsDisposed { get; private set; }

        public JsonSignAlgorithm Algorithm { get; private set; }
        
        #endregion

        #region Initialization

        internal JsonSignatureMethod(JsonSignAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case JsonSignAlgorithm.HS1:
                case JsonSignAlgorithm.HS256:
                case JsonSignAlgorithm.HS384:
                case JsonSignAlgorithm.HS512:
                    break;

                case JsonSignAlgorithm.RS1:
                case JsonSignAlgorithm.RS256:
                case JsonSignAlgorithm.RS384:
                case JsonSignAlgorithm.RS512:
                    break;

                case JsonSignAlgorithm.ES1:
                case JsonSignAlgorithm.ES256:
                case JsonSignAlgorithm.ES384:
                case JsonSignAlgorithm.ES512:

                    break;
                default:
                    throw new ArgumentOutOfRangeException("algorithm");
            }

            Algorithm = algorithm;
        }

        public static JsonSignatureMethod CreateRS(JsonSignAlgorithmRS algorithm, RSAParameters rsaParameters)
        {
            return new JsonSignatureMethodRS(algorithm, rsaParameters);
        }

        public static JsonSignatureMethod CreateRS(JsonSignAlgorithmRS algorithm, byte[] rsaParametersBytes)
        {
            var rsaParameters = JsonProcessor.Deserialize<RSAParameters>(rsaParametersBytes);
            return CreateRS(algorithm, rsaParameters);
        }

        public static JsonSignatureMethod CreateRS(JsonSignAlgorithmRS algorithm)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                return CreateRS(algorithm, rsa.ExportParameters(true));
            }
        }

        public static JsonSignatureMethod CreateHS(JsonSignAlgorithmHS algorithm, SecureString secret)
        {
            return new JsonSignatureMethodHS(algorithm, secret);
        }

        public static JsonSignatureMethod CreateES(JsonSignAlgorithmES algorithm, CngKey key)
        {
            return new JsonSignatureMethodES(algorithm, key);
        }

        public static JsonSignatureMethod CreateES(JsonSignAlgorithmES algorithm, byte[] keyBytes)
        {
            using (var key = CngKey.Import(keyBytes, CngKeyBlobFormat.EccPrivateBlob))
            {
                return CreateES(algorithm, key);
            }
        }

        public static JsonSignatureMethod CreateES(JsonSignAlgorithmES algorithm)
        {
            using (var es = new ECDsaCng())
            {
                return CreateES(algorithm, es.Key);
            }
        }

        #endregion

        #region Public methods

        public abstract string ComputeSignature(byte[] data);

        public abstract bool ValidateSignature(byte[] data, string signature);

        public abstract byte[] ExportKey(bool includePrivateKey);

        #endregion

        #region Implementation of IDisposable

        public virtual void Dispose()
        {
            if (!IsDisposed)
            {
                IsDisposed = true;
            }
        }

        #endregion

        #region ICloneable implementation

        public virtual JsonSignMateConfig Clone()
        {
            return new JsonSignMateConfig
            {
                Algor
                SignatureKey = SignatureKey,
                Method = Method
            };

        }

        object ICloneable.Clone()
        {
            return Clone();
        }

        #endregion
    }
}