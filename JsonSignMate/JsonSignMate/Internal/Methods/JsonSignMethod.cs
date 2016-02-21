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

namespace devSane.Json
{
    internal abstract class JsonSignMethod : IDisposable, ICloneable
    {
        #region Properties

        protected bool IsDisposed { get; private set; }

        public JsonSignAlgorithm Algorithm { get; private set; }
        
        #endregion

        #region Initialization

        internal JsonSignMethod(JsonSignAlgorithm algorithm)
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
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }

            Algorithm = algorithm;
        }

        #endregion

        #region Abstract methods

        public abstract string ComputeSignature(byte[] data);

        public abstract bool ValidateSignature(byte[] data, string signature);

        public abstract byte[] ExportKey(bool includePrivateKey);

        public abstract JsonSignMethod Clone();

        #endregion

        #region Protected methods

        protected void ThrowIfDisposed()
        {
            if (IsDisposed)
            {
                throw new ObjectDisposedException("JsonSignMethod is disposed.");
            }
        }

        #endregion

        #region IDisposable implementation

        public virtual void Dispose()
        {
            if (!IsDisposed)
            {
                IsDisposed = true;
            }
        }

        #endregion

        #region ICloneable implementation

        object ICloneable.Clone()
        {
            ThrowIfDisposed();
            return Clone();
        }

        #endregion
    }
}