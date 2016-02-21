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
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace devSane.Json.Tests
{
    [TestClass]
    public class SecureStringTests
    {
        [TestMethod]
        public void AppendCharsTest()
        {
            const string testStr = "test";
            var testChs = testStr.ToCharArray();

            using (var ss = new SecureString())
            {
                ss.AppendChars(testChs);
                ss.MakeReadOnly();

                Assert.AreEqual(testStr.Length, ss.Length);

                var ptr = IntPtr.Zero;
                try
                {
                    ptr = Marshal.SecureStringToGlobalAllocUnicode(ss);
                    var str = Marshal.PtrToStringUni(ptr, testStr.Length); // Attention: Unsafe function, for test purposes only
                    Assert.AreEqual(testStr, str);
                }
                finally
                {
                    if (ptr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(ptr);
                    }
                }
            }
        }

        [TestMethod]
        public void CloneTest()
        {
            var secretChs = new[] { 'T', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't' };
            var ss = new SecureString();
            ss.AppendChars(secretChs);
            ss.MakeReadOnly();

            var cloned = ss.Clone();
            Assert.AreNotEqual(ss, cloned);

            ss.Process(originalBytes =>
            {
                cloned.Process(clonedBytes =>
                {
                    CollectionAssert.AreEqual(originalBytes, clonedBytes);
                });
            });
        }

        [TestMethod]
        public void SecureStringProcessActionTest()
        {
            var secretChs = new[] {'T', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't'};
            var ss = new SecureString();
            ss.AppendChars(secretChs);
            ss.MakeReadOnly();

            ss.Process(bytes =>
            {
                var restoredSecret = Encoding.Unicode.GetString(bytes);
                var restoredSecretChs = restoredSecret.ToCharArray();

                CollectionAssert.AreEqual(secretChs, restoredSecretChs);
            });
        }

        [TestMethod]
        public void SecureStringProcessFuncTest()
        {
            var secretChs = new[] {'T', 'e', 's', 't', 'S', 'e', 'c', 'r', 'e', 't'};
            var ss = new SecureString();
            ss.AppendChars(secretChs);
            ss.MakeReadOnly();

            ss.Process(bytes =>
            {
                var restoredSecret = Encoding.Unicode.GetString(bytes);
                var restoredSecretChs = restoredSecret.ToCharArray();

                CollectionAssert.AreEqual(secretChs, restoredSecretChs);
                return true;
            });
        }

        [TestMethod]
        public void SecureStringProcessFuncResultTest()
        {
            var ss = new SecureString();

            var expectedRetVal = Guid.NewGuid();
            var actualRetVal = ss.Process(bytes => expectedRetVal);

            Assert.AreEqual(expectedRetVal, actualRetVal);
        }

    }
}