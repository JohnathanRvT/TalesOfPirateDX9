using System;
using System.Security.Cryptography;

class Test {
    static void Main() {
        Console.WriteLine($"Nonce sizes: {AesGcm.NonceByteSizes.Min} to {AesGcm.NonceByteSizes.Max} step {AesGcm.NonceByteSizes.Step}");
        try {
            var gcm = new AesGcm(new byte[16], 12);
            gcm.Encrypt(new byte[16], new byte[1], new byte[1], new byte[12]);
            Console.WriteLine("16 byte nonce worked!");
        } catch (Exception e) {
            Console.WriteLine($"16 byte nonce failed: {e.Message}");
        }
    }
}
