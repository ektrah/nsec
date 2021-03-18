// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the NOTICE file in the project root for more information.

using System;
using NSec.Cryptography;
using Xunit;

namespace NSec.Tests.Contrib
{
    public static class RandomTests
    {
        [Fact]
        public static void RandomDistribution()
        {
            byte[] random = new byte[2048];

            RandomGenerator.Default.GenerateBytes(random);

            VerifyRandomDistribution(random);
        }

        internal static void VerifyRandomDistribution(byte[] random)
        {
            // Better tests for randomness are available.  For now just use a simple
            // check that compares the number of 0s and 1s in the bits.
            VerifyNeutralParity(random);
        }

        private static void VerifyNeutralParity(byte[] random)
        {
            int zeroCount = 0, oneCount = 0;

            for (int i = 0; i < random.Length; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    if (((random[i] >> j) & 1) == 1)
                    {
                        oneCount++;
                    }
                    else
                    {
                        zeroCount++;
                    }
                }
            }

            // Over the long run there should be about as many 1s as 0s.
            // This isn't a guarantee, just a statistical observation.
            // Allow a 7% tolerance band before considering it to have gotten out of hand.
            double bitDifference = Math.Abs(zeroCount - oneCount) / (double)(zeroCount + oneCount);
            const double AllowedTolerance = 0.07;
            if (bitDifference > AllowedTolerance)
            {
                throw new InvalidOperationException("Expected bitDifference < " + AllowedTolerance + ", got " + bitDifference + ".");
            }
        }
    }
}
