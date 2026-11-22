using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;


namespace MfpEv2Issue
{

    public sealed class TransparentExchangeResult
    {
        public byte[] RawResponse { get; init; } = Array.Empty<byte>();

        // Ground-truth payload: bytes after C0 object and before final SW1SW2
        public byte[] Payload { get; init; } = Array.Empty<byte>();

        // C0 03 xx sw1 sw2
        public byte? C0ErrorObjectIndex { get; init; }
        public ushort? C0Sw { get; init; }

        // Final APDU SW1SW2
        public ushort? ApduSw { get; init; }

        public bool IsOk { get; init; }
    }



    // ---- Error types -------------------------------------------------------

    public interface IMifarePlusChannel
    {
        /// <summary>
        /// High-level MIFARE native exchange (wrapped / massaged)
        /// </summary>
        byte[] Transceive(byte[] command);

        /// <summary>
        /// Low-level raw PC/SC APDU exchange (no modification)
        /// </summary>
        byte[] TransceiveRaw(byte[] apdu);
        void ReconnectCard(); // NEW
    }

    public class MifarePlusException : Exception
    {
        public MifarePlusException(string message) : base(message) { }
    }

    public class InvalidResponseStatusException : MifarePlusException
    {
        public int Status { get; }
        public int? Status2 { get; }

        public InvalidResponseStatusException(int sw1)
            : base($"Invalid response status: 0x{sw1:X2}")
        {
            Status = sw1;
        }

        public InvalidResponseStatusException(int sw1, int sw2)
            : base($"Invalid response status: 0x{sw1:X2} 0x{sw2:X2}")
        {
            Status = sw1;
            Status2 = sw2;
        }
    }

    public class InvalidMacException : MifarePlusException
    {
        public InvalidMacException() : base("Invalid MAC") { }
    }

    public class LengthMismatchException : MifarePlusException
    {
        public int Expected { get; }
        public int Actual { get; }

        public LengthMismatchException(int expected, int actual)
            : base($"Length mismatch: expected={expected} actual={actual}")
        {
            Expected = expected;
            Actual = actual;
        }
    }

    public class CryptoErrorException : MifarePlusException
    {
        public CryptoErrorException(string msg) : base($"Crypto error: {msg}") { }
    }

    public class InvalidInputException : MifarePlusException
    {
        public InvalidInputException(string msg) : base($"Invalid input: {msg}") { }
    }

    // ---- Session struct ----------------------------------------------------

    public class FirstAuthResult
    {
        public int WCtr { get; set; }   // 0..0xFFFF
        public int RCtr { get; set; }
        public byte[] Ti { get; set; } = Array.Empty<byte>();
        public byte[] KeyEnc { get; set; } = Array.Empty<byte>();
        public byte[] KeyMac { get; set; } = Array.Empty<byte>();
    }




    // ---- Controller --------------------------------------------------------

    public partial class MifarePlusController
    {
        private readonly IMifarePlusChannel _channel;
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        private FirstAuthResult _session = new FirstAuthResult();

        public MifarePlusController(IMifarePlusChannel channel)
        {
            _channel = channel;
        }

        // PUBLIC: First authentication (mfpFirstAuth)

        public FirstAuthResult FirstAuth(
            byte[] key,
            int keyNumber,
            bool useRaw = false,   // default: wrapped Transceive
            byte[]? pcdCapabilities = null // null: six zero bytes; empty: omit capabilities, as in RFIDDiscover
        )
        {
            if (key == null || key.Length != 16)
                throw new InvalidInputException("key must be 16 bytes (AES-128)");
            if (keyNumber < 0 || keyNumber > ushort.MaxValue)
                throw new InvalidInputException("keyNumber must fit in two bytes");
            pcdCapabilities ??= new byte[6];
            if (pcdCapabilities.Length != 0 && pcdCapabilities.Length != 6)
                throw new InvalidInputException("pcdCapabilities must contain zero or six bytes");
            _session = new FirstAuthResult();

            // choose transport once
            Func<byte[], byte[]> xceive =
                useRaw ? _channel.TransceiveRaw : _channel.Transceive;

            byte[] sendBuf = new byte[256];
            byte[] receiveBuf = new byte[256];

            byte[] randA = new byte[16];
            byte[] randB = new byte[16];

            int wCtr = 0;
            int rCtr = 0;

            // --- First command: 0x70 (request random B) ---
            int pos = 0;
            sendBuf[pos++] = 0x70;
            sendBuf[pos++] = (byte)(keyNumber & 0x00FF);
            sendBuf[pos++] = (byte)((keyNumber >> 8) & 0x00FF);
            sendBuf[pos++] = (byte)pcdCapabilities.Length;
            foreach (byte capability in pcdCapabilities)
                sendBuf[pos++] = capability;

            wCtr = 0;
            rCtr = 0;

            byte[] cmd1 = new byte[pos];
            Array.Copy(sendBuf, cmd1, pos);

            // 🔽 CHANGED
            byte[] resp1 = xceive(cmd1);
            Array.Copy(resp1, receiveBuf, resp1.Length);
            int receivedBytes1 = resp1.Length;

            if (receivedBytes1 < 1)
                throw new InvalidResponseStatusException(0x00);

            if (receiveBuf[0] != 0x90)
                throw new InvalidResponseStatusException(receiveBuf[0] & 0xFF);

            if (receivedBytes1 < 1 + 16)
                throw new LengthMismatchException(17, receivedBytes1);

            byte[] encRandB = new byte[16];
            Array.Copy(receiveBuf, 1, encRandB, 0, 16);

            // Local auth1
            byte[] auth1Out = FirstAuth1(key, randA, randB, encRandB);

            // --- Second command: 0x72 + 32 bytes from auth1Out ---
            pos = 0;
            sendBuf[pos++] = 0x72;
            foreach (var b in auth1Out)
                sendBuf[pos++] = b;

            byte[] cmd2 = new byte[pos];
            Array.Copy(sendBuf, cmd2, pos);

            // 🔽 CHANGED
            byte[] resp2 = xceive(cmd2);
            Array.Copy(resp2, receiveBuf, resp2.Length);
            int receivedBytes2 = resp2.Length;

            if (receivedBytes2 < 1)
                throw new InvalidResponseStatusException(0x00);

            if (receiveBuf[0] != 0x90)
                throw new InvalidResponseStatusException(receiveBuf[0] & 0xFF);

            if (receivedBytes2 < 1 + 32)
                throw new LengthMismatchException(33, receivedBytes2);

            byte[] auth2In = new byte[32];
            Array.Copy(receiveBuf, 1, auth2In, 0, 32);
            byte[] auth2Out = FirstAuth2(key, randA, randB, auth2In);

            if (auth2Out.Length != 36)
                throw new LengthMismatchException(36, auth2Out.Length);

            byte[] ti = new byte[4];
            byte[] keyEnc = new byte[16];
            byte[] keyMac = new byte[16];

            Array.Copy(auth2Out, 0, ti, 0, 4);
            Array.Copy(auth2Out, 4, keyEnc, 0, 16);
            Array.Copy(auth2Out, 20, keyMac, 0, 16);

            wCtr = 0;
            rCtr = 0;

            var session = new FirstAuthResult
            {
                WCtr = wCtr,
                RCtr = rCtr,
                Ti = ti,
                KeyEnc = keyEnc,
                KeyMac = keyMac
            };

            _session = session;
            return session;
        }


        // Low-level transceive

        // Existing usage (unchanged)
        private byte[] Transceive(byte[] cmd)
            => _channel.Transceive(cmd);

        // 🔓 New: raw escape hatch
        public byte[] TransceiveRaw(byte[] apdu)
            => _channel.TransceiveRaw(apdu);

        public void ResetCard()
        {
            _session = new FirstAuthResult();
            _channel.ReconnectCard();
        }


        // ---- FirstAuth1 -----------------------------------------------------

        private byte[] FirstAuth1(
            byte[] key,
            byte[] randA,    // out
            byte[] randB,    // out
            byte[] encRandB  // in
        )
        {
            if (key.Length != 16)
                throw new InvalidInputException("key must be 16 bytes");
            if (encRandB.Length != 16)
                throw new InvalidInputException("encRandB must be 16 bytes");
            if (randA.Length != 16 || randB.Length != 16)
                throw new InvalidInputException("randA/randB must be 16 bytes");

            // generate 16-byte random A
            _rng.GetBytes(randA);

            byte[] ivZero = new byte[16];

            // AES-CBC decrypt encRandB
            byte[] decrypted = AesCbcDecrypt(key, ivZero, encRandB);
            Array.Copy(decrypted, randB, 16);

            // tempRandB = randB shifted left 1 byte
            byte[] tempRandB = (byte[])randB.Clone();
            byte extra = tempRandB[0];
            for (int i = 0; i < 15; i++)
                tempRandB[i] = tempRandB[i + 1];
            tempRandB[15] = extra;

            // data = randA || tempRandB
            byte[] data = new byte[32];
            Array.Copy(randA, 0, data, 0, 16);
            Array.Copy(tempRandB, 0, data, 16, 16);

            return AesCbcEncrypt(key, ivZero, data); // 32 bytes
        }

        // ---- FirstAuth2 -----------------------------------------------------

        private byte[] FirstAuth2(
            byte[] key,
            byte[] randA,
            byte[] randB,
            byte[] input     // 32 bytes
        )
        {
            if (key.Length != 16)
                throw new InvalidInputException("key must be 16 bytes");
            if (randA.Length != 16 || randB.Length != 16)
                throw new InvalidInputException("randA/randB must be 16 bytes");
            if (input.Length != 32)
                throw new InvalidInputException("input must be 32 bytes");

            byte[] ivZero = new byte[16];
            byte[] data = AesCbcDecrypt(key, ivZero, input); // 32 bytes

            // extra = data[19]; shift data[4..19] right by 1
            byte extra = data[19];
            int i = 19;
            while (i > 4)
            {
                data[i] = data[i - 1];
                i--;
            }
            data[4] = extra;

            // check randA'
            byte[] randAprime = new byte[16];
            Array.Copy(data, 4, randAprime, 0, 16);
            if (!BytesEqual(randAprime, randA))
                throw new InvalidInputException("randA mismatch in firstAuth2");

            byte[] result = new byte[36];

            // TI = data[0..3]
            Array.Copy(data, 0, result, 0, 4);

            // KEY_ENC
            byte[] keyEnc = new byte[16];

            for (int j = 0; j < 5; j++)
                keyEnc[j] = randA[11 + j];

            for (int j = 0; j < 5; j++)
                keyEnc[5 + j] = randB[11 + j];

            for (int j = 0; j < 5; j++)
                keyEnc[10 + j] = (byte)(randA[4 + j] ^ randB[4 + j]);

            keyEnc[15] = 0x11;

            byte[] encKeyEnc = AesCbcEncrypt(key, ivZero, keyEnc);
            Array.Copy(encKeyEnc, 0, result, 4, 16);

            // KEY_MAC
            byte[] keyMac = new byte[16];
            for (int j = 0; j < 5; j++)
                keyMac[j] = randA[7 + j];

            for (int j = 0; j < 5; j++)
                keyMac[5 + j] = randB[7 + j];

            for (int j = 0; j < 5; j++)
                keyMac[10 + j] = (byte)(randA[j] ^ randB[j]);

            keyMac[15] = 0x22;

            byte[] encKeyMac = AesCbcEncrypt(key, ivZero, keyMac);
            Array.Copy(encKeyMac, 0, result, 20, 16);

            return result;
        }

        // ---- Read (mfpRead) -------------------------------------------------

        public byte[] ReadBlocks(int blockNumber, int blockCount)
        {
            if (_session.Ti == null || _session.Ti.Length != 4)
                throw new InvalidInputException("TI must be 4 bytes");
            if (_session.KeyMac == null || _session.KeyMac.Length != 16)
                throw new InvalidInputException("keyMac must be 16 bytes");

            byte[] macSendBuf = new byte[4096];
            byte[] sendBuf = new byte[128];
            byte[] receiveBuf = new byte[4096];

            int sentBytes = 0;

            // Command header
            sendBuf[sentBytes++] = 0x33;
            sendBuf[sentBytes++] = (byte)(blockNumber & 0x00FF);
            sendBuf[sentBytes++] = (byte)((blockNumber >> 8) & 0x00FF);
            sendBuf[sentBytes++] = (byte)blockCount;

            // --- Calculate CMAC (request) ---
            macSendBuf[0] = 0x33;
            macSendBuf[1] = (byte)(_session.RCtr & 0x00FF);
            macSendBuf[2] = (byte)((_session.RCtr >> 8) & 0x00FF);
            macSendBuf[3] = _session.Ti[0];
            macSendBuf[4] = _session.Ti[1];
            macSendBuf[5] = _session.Ti[2];
            macSendBuf[6] = _session.Ti[3];
            macSendBuf[7] = (byte)(blockNumber & 0x00FF);
            macSendBuf[8] = (byte)((blockNumber >> 8) & 0x00FF);
            macSendBuf[9] = (byte)blockCount;

            byte[] macReq = AesCmac(_session.KeyMac, Slice(macSendBuf, 0, 10));

            // append 8 odd CMAC bytes
            for (int idx = 0; idx < 16; idx++)
            {
                if ((idx % 2) == 1)
                    sendBuf[sentBytes++] = macReq[idx];
            }

            byte[] cmd = Slice(sendBuf, 0, sentBytes);
            byte[] resp = Transceive(cmd);
            Array.Copy(resp, receiveBuf, resp.Length);
            int receivedBytes = resp.Length;

            _session.RCtr = (_session.RCtr + 1) & 0xFFFF;

            if (receivedBytes < 1)
                throw new InvalidResponseStatusException(0x00);
            if (receiveBuf[0] != 0x90)
                throw new InvalidResponseStatusException(receiveBuf[0] & 0xFF);

            int dataLen = receivedBytes - 9; // SC + 8-byte MAC
            int expectedLen = blockCount * 16;
            if (dataLen != expectedLen)
                throw new LengthMismatchException(expectedLen, dataLen);

            // --- Check MAC on response ---
            macSendBuf[0] = receiveBuf[0];
            macSendBuf[1] = (byte)(_session.RCtr & 0x00FF);
            macSendBuf[2] = (byte)((_session.RCtr >> 8) & 0x00FF);
            // bytes 3..9: TI + block info from request still in buffer

            int dataStart = 1;
            int dataEnd = 1 + dataLen;
            byte[] respDataSlice = Slice(receiveBuf, dataStart, dataLen);
            Array.Copy(respDataSlice, 0, macSendBuf, 10, dataLen);

            int macMsgLen = 10 + dataLen;
            byte[] macResp = AesCmac(_session.KeyMac, Slice(macSendBuf, 0, macMsgLen));

            int macStart = receivedBytes - 8;
            for (int idx = 0; idx < 16; idx++)
            {
                if ((idx % 2) == 1)
                {
                    if (receiveBuf[macStart] != macResp[idx])
                        throw new InvalidMacException();
                    macStart++;
                }
            }

            // MAC ok
            return Slice(receiveBuf, 1, dataLen);
        }

        // ---- AES helpers ----------------------------------------------------

        private static byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] input)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                aes.IV = iv;

                using var encryptor = aes.CreateEncryptor();
                return encryptor.TransformFinalBlock(input, 0, input.Length);
            }
            catch (Exception ex)
            {
                throw new CryptoErrorException("AES CBC encrypt failed: " + ex.Message);
            }
        }

        private static byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] input)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                aes.IV = iv;

                using var decryptor = aes.CreateDecryptor();
                return decryptor.TransformFinalBlock(input, 0, input.Length);
            }
            catch (Exception ex)
            {
                throw new CryptoErrorException("AES CBC decrypt failed: " + ex.Message);
            }
        }

        // AES-ECB (single block) used for CMAC
        private static byte[] AesEcbEncryptBlock(byte[] key, byte[] block)
        {
            if (block.Length != 16)
                throw new ArgumentException("Block must be 16 bytes", nameof(block));

            try
            {
                using var aes = Aes.Create();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = key;

                using var encryptor = aes.CreateEncryptor();
                return encryptor.TransformFinalBlock(block, 0, 16);
            }
            catch (Exception ex)
            {
                throw new CryptoErrorException("AES ECB encrypt failed: " + ex.Message);
            }
        }

        // ---- AES-CMAC (RFC 4493) -------------------------------------------

        private static byte[] AesCmac(byte[] key, byte[] message)
        {
            const int blockSize = 16;
            byte rb = 0x87;

            static byte[] LeftShiftOne(byte[] block)
            {
                var outBuf = new byte[block.Length];
                int carry = 0;
                for (int i = block.Length - 1; i >= 0; i--)
                {
                    int v = block[i] & 0xFF;
                    outBuf[i] = (byte)((v << 1) | carry);
                    carry = (v >> 7) & 0x01;
                }
                return outBuf;
            }

            byte[] zeroBlock = new byte[blockSize];
            byte[] L = AesEcbEncryptBlock(key, zeroBlock);

            byte[] k1 = LeftShiftOne(L);
            if ((L[0] & 0x80) != 0)
                k1[blockSize - 1] ^= rb;

            byte[] k2 = LeftShiftOne(k1);
            if ((k1[0] & 0x80) != 0)
                k2[blockSize - 1] ^= rb;

            if (message.Length == 0)
            {
                // special case: 1 block of padding only
                byte[] mLast = new byte[blockSize];
                mLast[0] = 0x80;
                for (int i = 0; i < blockSize; i++)
                    mLast[i] ^= k2[i];

                byte[] x = new byte[blockSize]; // zeros
                byte[] y = new byte[blockSize];
                for (int i = 0; i < blockSize; i++)
                    y[i] = (byte)(x[i] ^ mLast[i]);

                return AesEcbEncryptBlock(key, y);
            }

            int n = (message.Length + blockSize - 1) / blockSize;
            bool lastComplete = (message.Length % blockSize) == 0;

            int lastBlockStart = (n - 1) * blockSize;
            byte[] mLast2 = new byte[blockSize];

            if (lastComplete)
            {
                Array.Copy(message, lastBlockStart, mLast2, 0, blockSize);
                for (int i = 0; i < blockSize; i++)
                    mLast2[i] ^= k1[i];
            }
            else
            {
                int lastLen = message.Length - lastBlockStart;
                Array.Copy(message, lastBlockStart, mLast2, 0, lastLen);
                mLast2[lastLen] = 0x80;
                for (int i = 0; i < blockSize; i++)
                    mLast2[i] ^= k2[i];
            }

            byte[] xBuf = new byte[blockSize]; // zeros

            // process all but last block
            if (n > 1)
            {
                for (int blk = 0; blk < n - 1; blk++)
                {
                    byte[] block = new byte[blockSize];
                    Array.Copy(message, blk * blockSize, block, 0, blockSize);

                    byte[] tmp = new byte[blockSize];
                    for (int i = 0; i < blockSize; i++)
                        tmp[i] = (byte)(xBuf[i] ^ block[i]);

                    xBuf = AesEcbEncryptBlock(key, tmp);
                }
            }

            byte[] yBuf = new byte[blockSize];
            for (int i = 0; i < blockSize; i++)
                yBuf[i] = (byte)(xBuf[i] ^ mLast2[i]);

            return AesEcbEncryptBlock(key, yBuf);
        }

        // ---- Small helpers --------------------------------------------------

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        private static byte[] Slice(byte[] source, int offset, int length)
        {
            byte[] dst = new byte[length];
            Array.Copy(source, offset, dst, 0, length);
            return dst;
        }

        public TransparentExchangeResult TransparentExchange(
            byte[] payload,
            uint? timeoutUs = 1_000_000,     // 5F46 04 TIME (LSB first); null => omit
            byte? transceiveFlag = null,     // 90 02 [Flag] 00 (optional)
            byte? txNumBit = null            // 91 01 [NumBit] (optional)
        )
        {
            if (payload == null || payload.Length == 0)
                throw new InvalidInputException("payload cannot be empty");

            // --------------------
            // Build Cmd TLV field
            // --------------------
            var tlvs = new List<byte>(64);

            // Optional: 90 02 [Flag] 00
            if (transceiveFlag.HasValue)
            {
                tlvs.Add(0x90);
                tlvs.Add(0x02);
                tlvs.Add(transceiveFlag.Value);
                tlvs.Add(0x00);
            }

            // Optional: 91 01 [NumBit]
            if (txNumBit.HasValue)
            {
                tlvs.Add(0x91);
                tlvs.Add(0x01);
                tlvs.Add((byte)(txNumBit.Value & 0x07));
            }

            // Optional: 5F46 04 [TIME little-endian]
            if (timeoutUs.HasValue)
            {
                tlvs.Add(0x5F);
                tlvs.Add(0x46);
                tlvs.Add(0x04);

                uint t = timeoutUs.Value;
                tlvs.Add((byte)(t & 0xFF));
                tlvs.Add((byte)((t >> 8) & 0xFF));
                tlvs.Add((byte)((t >> 16) & 0xFF));
                tlvs.Add((byte)((t >> 24) & 0xFF));
            }

            // Required: 95 [BER length] [payload bytes]
            tlvs.Add(0x95);
            tlvs.AddRange(EncodeBerLength(payload.Length));
            tlvs.AddRange(payload);

            if (tlvs.Count > 255)
                throw new InvalidInputException($"TransparentExchange Cmd TLV too long (Lc={tlvs.Count})");

            // --------------------
            // Build APDU
            // FF C2 00 01 Lc <TLVs> 00
            // --------------------
            var apdu = new List<byte>(5 + tlvs.Count + 1)
            {
                0xFF, 0xC2, 0x00, 0x01, (byte)tlvs.Count
            };
            apdu.AddRange(tlvs);
            apdu.Add(0x00); // Le

            // Send
            byte[] rawResp = _channel.TransceiveRaw(apdu.ToArray());
            if (rawResp == null) rawResp = Array.Empty<byte>();

            // Parse per your logs:
            // DataOut: C0 03 xx sw1 sw2 <raw payload bytes...>
            // Final APDU SW1SW2 is last 2 bytes
            var parsed = ParseC0StyleResponse(rawResp);

            return new TransparentExchangeResult
            {
                RawResponse = rawResp,
                Payload = parsed.Payload,
                C0ErrorObjectIndex = parsed.C0Idx,
                C0Sw = parsed.C0Sw,
                ApduSw = parsed.ApduSw,
                IsOk = parsed.Ok
            };
        }

        // =============================================================
        // Helpers (keep inside MifarePlusController)
        // =============================================================

        private sealed class ParsedC0Response
        {
            public byte[] Payload { get; init; } = Array.Empty<byte>();
            public byte? C0Idx { get; init; }
            public ushort? C0Sw { get; init; }
            public ushort? ApduSw { get; init; }
            public bool Ok { get; init; }
        }

        private static ParsedC0Response ParseC0StyleResponse(byte[] resp)
        {
            // Minimum: C0 03 xx sw1 sw2 + final sw1 sw2 = 7 bytes
            if (resp == null || resp.Length < 7)
                return new ParsedC0Response { Ok = false };

            ushort apduSw = (ushort)((resp[^2] << 8) | resp[^1]);

            int dataOutLen = resp.Length - 2;  // everything except final SW1SW2
            if (dataOutLen < 5)
                return new ParsedC0Response { ApduSw = apduSw, Ok = false };

            // Must start with C0 03
            if (resp[0] != 0xC0 || resp[1] != 0x03)
                return new ParsedC0Response { ApduSw = apduSw, Ok = false };

            byte idx = resp[2];
            ushort c0Sw = (ushort)((resp[3] << 8) | resp[4]);

            // Payload is raw bytes after 5-byte C0 object, before final SW1SW2
            int payloadOffset = 5;
            int payloadLen = dataOutLen - payloadOffset;
            byte[] payload = payloadLen > 0 ? Slice(resp, payloadOffset, payloadLen) : Array.Empty<byte>();

            bool ok = (apduSw == 0x9000) && (idx == 0x00) && (c0Sw == 0x9000);

            return new ParsedC0Response
            {
                Payload = payload,
                C0Idx = idx,
                C0Sw = c0Sw,
                ApduSw = apduSw,
                Ok = ok
            };
        }

        private static IEnumerable<byte> EncodeBerLength(int len)
        {
            if (len < 0) throw new ArgumentOutOfRangeException(nameof(len));
            if (len <= 0x7F) return new[] { (byte)len };
            if (len <= 0xFF) return new[] { (byte)0x81, (byte)len };
            if (len <= 0xFFFF) return new[] { (byte)0x82, (byte)(len >> 8), (byte)(len & 0xFF) };
            throw new ArgumentOutOfRangeException(nameof(len), "BER length too large");
        }


        private sealed class TransparentParsed
        {
            public byte[] Data97 { get; init; } = Array.Empty<byte>();
            public byte? NumBit92 { get; init; }
            public byte? Status96 { get; init; }
            public bool IsOk { get; init; }
            public ushort? Sw { get; init; }
        }
        private static TransparentParsed ParseTransparentResponse(byte[] resp)
        {
            if (resp == null || resp.Length == 0)
                return new TransparentParsed { IsOk = false };

            // Detect SW1SW2 at end (typical APDU style)
            ushort? sw = null;
            bool swOk = false;
            int end = resp.Length;

            if (resp.Length >= 2)
            {
                sw = (ushort)((resp[^2] << 8) | resp[^1]);
                swOk = (sw == 0x9000);
                // If it looks like SW1SW2, parse TLVs from resp[0..len-2]
                end = resp.Length - 2;
            }

            // If device returns leading 0x90 success (your legacy style)
            if (resp[0] == 0x90 && (resp.Length == 1 || (resp[1] != 0x92 && resp[1] != 0x96 && resp[1] != 0x97)))
            {
                return new TransparentParsed
                {
                    Data97 = resp.Length > 1 ? resp.Skip(1).ToArray() : Array.Empty<byte>(),
                    IsOk = true,
                    Sw = null
                };
            }

            byte[] data97 = Array.Empty<byte>();
            byte? numBit92 = null;
            byte? status96 = null;

            int offset = 0;
            while (offset < end)
            {
                byte tag = resp[offset++];

                if (offset >= end) break;

                var (len, lenBytes) = DecodeBerLength(resp, offset, end);
                if (len < 0) break;
                offset += lenBytes;

                if (offset + len > end) break;

                if (tag == 0x92 && len == 1)
                    numBit92 = resp[offset];
                else if (tag == 0x96 && len >= 1)
                    status96 = resp[offset]; // first status byte
                else if (tag == 0x97)
                    data97 = resp.Skip(offset).Take(len).ToArray();

                offset += len;
            }

            return new TransparentParsed
            {
                Data97 = data97,
                NumBit92 = numBit92,
                Status96 = status96,
                IsOk = swOk || sw is null, // if no SW, assume ok-ish; caller can inspect Status96
                Sw = sw
            };
        }

        public sealed class CardInformation
        {
            public byte[]? Uid { get; init; }
            public byte[]? Ats { get; init; }

        }

        /// <summary>
        /// Gets card information using PC/SC pseudo APDU (FF CA).
        /// Uses TransceiveRaw – no wrapping.
        /// </summary>
        public CardInformation GetCardInformation(bool getAts = false)
        {
            byte p1 = getAts ? (byte)0x01 : (byte)0x00;

            byte[] apdu =
            {
        0xFF, 0xCA, p1, 0x00, 0x00
    };

            byte[] resp = _channel.TransceiveRaw(apdu);

            if (resp == null || resp.Length == 0)
                throw new InvalidResponseStatusException(0x00);

            byte sw1;

            int dataLen;

            if (resp.Length >= 2 && resp[^2] == 0x90 && resp[^1] == 0x00)
            {
                // Standard ISO case
                sw1 = 0x90;

                dataLen = resp.Length - 2;
            }
            else if (resp[^1] == 0x90)
            {
                // ACS-style success: SW1 only
                sw1 = 0x90;
                dataLen = resp.Length - 1;
            }
            else
            {
                // Error case
                sw1 = resp[^1];
                throw new InvalidResponseStatusException(sw1);
            }

            byte[] data = dataLen > 0
                ? Slice(resp, 0, dataLen)
                : Array.Empty<byte>();

            return getAts
                ? new CardInformation { Ats = data }
                : new CardInformation { Uid = data };
        }




        public byte[] GetUid()
        {
            byte[] apdu = { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
            var resp = _channel.TransceiveRaw(apdu);

            if (resp == null || resp.Length < 1)
                throw new InvalidResponseStatusException(0x00);

            byte sw1 = resp[^1];

            if (sw1 != 0x90)
                throw new InvalidResponseStatusException(sw1);

            return resp.Take(resp.Length - 1).ToArray();
        }

        public byte[] GetAts()
        {
            byte[] apdu = { 0xFF, 0xCA, 0x01, 0x00, 0x00 };
            var resp = _channel.TransceiveRaw(apdu);

            if (resp == null || resp.Length < 1)
                throw new InvalidResponseStatusException(0x00);

            byte sw1 = resp[^1];

            if (sw1 != 0x90)
                throw new InvalidResponseStatusException(sw1);

            return resp.Take(resp.Length - 1).ToArray();
        }

        public sealed class PiccInformation
        {
            // Type A
            public byte[]? Atqa { get; init; }   // 2 bytes
            public byte[]? Uid { get; init; }    // 4 / 7 / 10 bytes
            public byte? Sak { get; init; }      // 1 byte

            // Type B
            public byte[]? Atqb { get; init; }   // 12 bytes

            public bool IsTypeA => Atqa != null;
            public bool IsTypeB => Atqb != null;
        }

        public PiccInformation GetPiccInformation()
        {
            byte[] apdu = { 0xFF, 0xCA, 0x00, 0x02, 0x00 };

            byte[] resp = _channel.TransceiveRaw(apdu);

            if (resp == null || resp.Length < 1)
                throw new InvalidResponseStatusException(0x00);

            // Accept standard PC/SC 90 00 and the reference reader's legacy single 90.
            int dataLen;
            if (resp.Length >= 2 && resp[^2] == 0x90 && resp[^1] == 0x00)
                dataLen = resp.Length - 2;
            else if (resp[^1] == 0x90)
                dataLen = resp.Length - 1;
            else if (resp.Length >= 2)
                throw new InvalidResponseStatusException(resp[^2], resp[^1]);
            else
                throw new InvalidResponseStatusException(resp[0]);
            if (dataLen <= 0)
                throw new Exception("Empty PICC data");

            byte[] data = resp.Take(dataLen).ToArray();

            // ---- Detect Type A or Type B ----

            // Type B → 12 bytes ATQB
            if (data.Length == 12)
            {
                return new PiccInformation
                {
                    Atqb = data
                };
            }

            // Type A → ATQA(2) + UID(4/7/10) + SAK(1)
            if (data.Length is 7 or 10 or 13) // ATQA + 4/7/10-byte UID + SAK
            {
                byte[] atqa = data.Take(2).ToArray();
                byte sak = data[^1];

                byte[] uid = data
                    .Skip(2)
                    .Take(data.Length - 3)
                    .ToArray();

                return new PiccInformation
                {
                    Atqa = atqa,
                    Uid = uid,
                    Sak = sak
                };
            }

            throw new Exception("Unexpected PICC data length");
        }


        /// <summary>
        /// Shared helper for ACS "Get Data" pseudo APDU (FF CA).
        /// Returns "data out" (UID or ATS) with status stripped.
        /// </summary>
        private byte[] GetData_FFCA(byte p1)
        {
            byte[] apdu = { 0xFF, 0xCA, p1, 0x00, 0x00 };

            byte[] resp = _channel.TransceiveRaw(apdu);
            if (resp == null || resp.Length < 2)
                throw new InvalidResponseStatusException(0x00);

            // Most readers: data ... 90 00
            if (resp.Length >= 2 && resp[^2] == 0x90 && resp[^1] == 0x00)
                return resp[..^2];

            // Some weird variants - treat last bytes as status anyway
            byte sw1 = resp[^2];
            byte sw2 = resp[^1];
            throw new InvalidResponseStatusException(sw1, sw2);
        }



        private static (int len, int lenBytes) DecodeBerLength(byte[] buf, int offset, int end)
        {
            if (offset >= end) return (-1, 0);

            int b0 = buf[offset] & 0xFF;
            if (b0 <= 0x7F) return (b0, 1);

            int n = b0 & 0x7F;
            if (n == 0 || n > 2) return (-1, 1);
            if (offset + 1 + n > end) return (-1, 1);

            int len = 0;
            for (int i = 0; i < n; i++)
                len = (len << 8) | (buf[offset + 1 + i] & 0xFF);

            return (len, 1 + n);
        }

        /// <summary>
        /// MIFARE Plus "Write Perso" (A8) sent through Transparent Exchange.
        /// Command: [A8][BNr(2 bytes)][Data(16 bytes)]
        /// Response: 1 byte status code (returned by PICC).
        /// You requested: ignore ACK/NAK; return only status.
        /// </summary>
        /// <param name="blockNumber">BNr, 0..65535 (sent LSB first)</param>
        /// <param name="data16">16 bytes to write (plain)</param>
        /// <param name="timeoutUs">Optional 5F46 timeout in microseconds for transparent exchange</param>
        /// <returns>Status code byte from card</returns>
        public byte WritePerso(ushort blockNumber, byte[] data16, uint? timeoutUs = 1_000_000)
        {
            if (data16 == null || data16.Length != 16)
                throw new InvalidInputException("WritePerso: data must be exactly 16 bytes");

            var cmd = new byte[1 + 2 + 16];
            int p = 0;
            cmd[p++] = 0xA8;
            cmd[p++] = (byte)(blockNumber & 0xFF);         // LSB
            cmd[p++] = (byte)((blockNumber >> 8) & 0xFF);  // MSB
            Array.Copy(data16, 0, cmd, p, 16);

            var res = _channel.Transceive(cmd);

            if (res == null || res.Length < 1)
                throw new LengthMismatchException(1, res?.Length ?? 0);

            if (res[0] != 0x90)
                throw new InvalidResponseStatusException(res[0] & 0xFF);

            // Per your instruction: ignore ACK/NAK, take status code byte
            return res[0];
        }
        public MfpStatusCode CommitPerso(uint? timeoutUs = 2_000_000)
        {
            var res = _channel.Transceive(new byte[] { 0xAA });

            if (res == null || res.Length < 1)
                throw new LengthMismatchException(1, res?.Length ?? 0);

            if (res[0] != 0x90)
                throw new InvalidResponseStatusException(res[0] & 0xFF);

            return (MfpStatusCode)res[0];
        }

        public enum MfpStatusCode : byte
        {
            // From your table snapshot (common ones)
            TransferCannotBeGranted = 0x00,
            WrongCrcIn1stPackage = 0x05,
            WrongCrcIn2ndPackage = 0x01,
            ConditionsNotSatisfied = 0x04,

            AuthenticationError = 0x06,
            CommandOverflow = 0x07,
            InvalidMac = 0x08,
            InvalidBlockNumber = 0x09,
            NotExistingBlockNumber = 0x0A,
            CmdNotAvailableInState = 0x0B,
            LengthError = 0x0C,
            GeneralManipulationError = 0x0F,

            // Also seen in spec as generic "ok" status byte
            Success90 = 0x90,

            // Some docs say ACK = 0x0A (Acknowledge) in (NAK/ACK) mode
            AcknowledgeA = 0x0A,
        }

        /// <summary>
        /// 3) ISO 14443-4A Active.
        /// Exact APDU (per your logs/spec):
        ///   FF C2 00 02 04 8F 02 00 04 00
        /// Response is parsed via the same C0-style rule you already use.
        /// Payload typically contains ATR-like bytes (per your logs).
        /// </summary>
        public TransparentExchangeResult Iso14443_4A_Active()
        {
            // P2 = 0x02 (Switch Protocol)
            // Lc = 0x04
            // Data = 8F 02 00 04
            // Le = 0x00
            byte[] data = new byte[] { 0x8F, 0x02, 0x00, 0x04 };
            return SendC2Apdu(p2: 0x02, data: data, le: 0x00);
        }

        /// <summary>
        /// 4) Set PCB to 0x0A and enable CRC, parity and protocol prologue in transmit data.
        /// Exact APDU (per your example):
        ///   FF C2 00 01 0A 90 02 00 00 FF 6E 03 07 01 0A
        /// Response: C0 03 00 90 00 90 00 (typical "No Error")
        /// </summary>
        /// <param name="pcb">PCB value (example uses 0x0A)</param>
        public TransparentExchangeResult SetPcbAndEnableCrcParityPrologue(byte pcb = 0x02)
        {
            // Data field is exactly the TLV sequence shown in your command example.
            // 90 02 00 00
            // FF 6E 03 07 01 <pcb>
            byte[] data = new byte[]
            {
        0x90, 0x02, 0x00, 0x00,
        0xFF, 0x6E, 0x03, 0x07, 0x01, pcb
            };

            // P2 = 0x01 (Transparent Exchange)
            return SendC2Apdu(p2: 0x01, data: data, le: 0x00);
        }

        // ------------------------------------------------------------
        // Private helper: send generic FF C2 00 <P2> <Lc> <Data> <Le>
        // and parse via your C0-style response parser.
        // ------------------------------------------------------------
        private TransparentExchangeResult SendC2Apdu(byte p2, byte[] data, byte le = 0x00)
        {
            data ??= Array.Empty<byte>();
            if (data.Length > 255)
                throw new InvalidInputException($"C2 APDU data too long (Lc={data.Length})");

            var apdu = new byte[5 + data.Length + 1];
            int p = 0;

            apdu[p++] = 0xFF;             // CLA
            apdu[p++] = 0xC2;             // INS
            apdu[p++] = 0x00;             // P1
            apdu[p++] = p2;               // P2 (Function)
            apdu[p++] = (byte)data.Length;// Lc
            Array.Copy(data, 0, apdu, p, data.Length);
            p += data.Length;
            apdu[p++] = le;               // Le

            byte[] rawResp = _channel.TransceiveRaw(apdu);
            rawResp ??= Array.Empty<byte>();

            // Use your ground-truth parsing logic (C0 object + payload + final SW1SW2)
            var parsed = ParseC0StyleResponse(rawResp);

            // Also extract the C0 object info (index + sw) if present
            byte? c0Idx = null;
            ushort? c0Sw = null;
            if (rawResp.Length >= 7 && rawResp[0] == 0xC0 && rawResp[1] == 0x03)
            {
                c0Idx = rawResp[2];
                c0Sw = (ushort)((rawResp[3] << 8) | rawResp[4]);
            }

            ushort? apduSw = rawResp.Length >= 2
                ? (ushort)((rawResp[^2] << 8) | rawResp[^1])
                : null;

            return new TransparentExchangeResult
            {
                RawResponse = rawResp,
                Payload = parsed.Payload,
                C0ErrorObjectIndex = c0Idx,
                C0Sw = c0Sw,
                ApduSw = apduSw,
                IsOk = parsed.Ok
            };
        }

    }
}
