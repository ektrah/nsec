// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the NOTICE file in the project root for more information.

using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Contrib
{
    public static class FixedTimeEqualsTests
    {
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(128 / 8)]
        [InlineData(256 / 8)]
        [InlineData(512 / 8)]
        [InlineData(96)]
        [InlineData(128)]
        public static unsafe void EqualReturnsTrue(int byteLength)
        {
            byte* left = stackalloc byte[byteLength];
            RandomGenerator.Default.GenerateBytes(new Span<byte>(left, byteLength));

            byte* right = stackalloc byte[byteLength];
            Unsafe.CopyBlockUnaligned(right, left, (uint)byteLength);

            bool isEqual = CryptographicOperations.FixedTimeEquals(left, right, byteLength);

            Assert.True(isEqual);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(128 / 8)]
        [InlineData(256 / 8)]
        [InlineData(512 / 8)]
        [InlineData(96)]
        [InlineData(128)]
        public static unsafe void UnequalReturnsFalse(int byteLength)
        {
            byte* left = stackalloc byte[byteLength];
            RandomGenerator.Default.GenerateBytes(new Span<byte>(left, byteLength));

            byte* right = stackalloc byte[byteLength];
            Unsafe.CopyBlockUnaligned(right, left, (uint)byteLength);

            left[left[0] % byteLength] ^= 0xFF;

            bool isEqual = CryptographicOperations.FixedTimeEquals(left, right, byteLength);

            Assert.False(isEqual);
        }

        [Fact]
        public static void HasCorrectMethodImpl()
        {
            Type t = typeof(CryptographicOperations);
            MethodInfo? mi = t.GetMethod(nameof(CryptographicOperations.FixedTimeEquals));

            // This method cannot be optimized, or it loses its fixed time guarantees.
            // It cannot be inlined, or it loses its no-optimization guarantee.
            Assert.Equal(
                MethodImplAttributes.NoInlining | MethodImplAttributes.NoOptimization,
                mi?.MethodImplementationFlags);
        }
    }
}
