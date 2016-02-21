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

using System.Collections.Generic;
using System.Runtime.InteropServices;

// ReSharper disable once CheckNamespace
namespace System.Security
{
    public static class SecureStringExtensions
    {
        public static void AppendChars(this SecureString secureStr, IEnumerable<char> chs)
        {
            if (secureStr == null) throw new ArgumentNullException(nameof(secureStr));
            if (chs == null) throw new ArgumentNullException(nameof(chs));

            foreach (var ch in chs)
            {
                secureStr.AppendChar(ch);
            }
        }

        public static T Process<T>(this SecureString secureStr, Func<byte[], T> handlerFn)
        {
            if (secureStr == null) throw new ArgumentNullException(nameof(secureStr));
            if (handlerFn == null) throw new ArgumentNullException(nameof(handlerFn));

            if (secureStr.Length == 0)
            {
                return handlerFn(new byte[0]);
            }

            var unmanagedStrPtr = IntPtr.Zero;
            var bytes = new byte[secureStr.Length * sizeof(char)];

            try
            {
                unmanagedStrPtr = Marshal.SecureStringToGlobalAllocUnicode(secureStr);

                Marshal.Copy(unmanagedStrPtr, bytes, 0, bytes.Length);

                return handlerFn(bytes);
            }
            finally
            {
                Array.Clear(bytes, 0, bytes.Length);

                if (unmanagedStrPtr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(unmanagedStrPtr);
                }
            }
        }

        public static void Process(this SecureString secureStr, Action<byte[]> handlerFn)
        {
            if (secureStr == null) throw new ArgumentNullException(nameof(secureStr));
            if (handlerFn == null) throw new ArgumentNullException(nameof(handlerFn));

            var wrapHandlerFn = new Func<byte[], bool>(bytes =>
            {
                handlerFn(bytes);
                return true;
            });

            Process(secureStr, wrapHandlerFn);
        }
    }
}