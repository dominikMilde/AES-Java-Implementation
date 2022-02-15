package hr.fer.kik.aes;

import java.nio.ByteBuffer;

public class AES128 {

    private static final int rcon[] = {
            0x01000000, 0x01000000, 0x02000000, 0x04000000,
            0x08000000, 0x10000000, 0x20000000, 0x40000000,
            0x80000000, 0x1b000000, 0x36000000, 0x6c000000};

    private static final byte[][] sbox = {
            {(byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f, (byte) 0xc5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, (byte) 0x76},
            {(byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72, (byte) 0xc0},
            {(byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7, (byte) 0xcc, (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31, (byte) 0x15},
            {(byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9a, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2, (byte) 0x75},
            {(byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a, (byte) 0xa0, (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f, (byte) 0x84},
            {(byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1, (byte) 0x5b, (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58, (byte) 0xcf},
            {(byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f, (byte) 0xa8},
            {(byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2},
            {(byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19, (byte) 0x73},
            {(byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b, (byte) 0xdb},
            {(byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, (byte) 0x79},
            {(byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e, (byte) 0xa9, (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae, (byte) 0x08},
            {(byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a},
            {(byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6, (byte) 0x0e, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d, (byte) 0x9e},
            {(byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28, (byte) 0xdf},
            {(byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16}
    };

    private static final byte[][] sboxInv = {
            {(byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5, (byte) 0x38, (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb},
            {(byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff, (byte) 0x87, (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb},
            {(byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23, (byte) 0x3d, (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3, (byte) 0x4e},
            {(byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24, (byte) 0xb2, (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1, (byte) 0x25},
            {(byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6, (byte) 0x92},
            {(byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84},
            {(byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, (byte) 0x0a, (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45, (byte) 0x06},
            {(byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f, (byte) 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a, (byte) 0x6b},
            {(byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, (byte) 0x73},
            {(byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf, (byte) 0x6e},
            {(byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5, (byte) 0x89, (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe, (byte) 0x1b},
            {(byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79, (byte) 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a, (byte) 0xf4},
            {(byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7, (byte) 0x31, (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec, (byte) 0x5f},
            {(byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a, (byte) 0x0d, (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef},
            {(byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61},
            {(byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6, (byte) 0x26, (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c, (byte) 0x7d}
    };

    static private int Nr = 10;
    static private int Nb = 4;
    static private int Nk = 4;

    public static byte[] encryptECB(byte[] arg, byte[] key) {
        int[] keysExp = createKeyExpansion(key);
        byte[] argPadding = addPadding(arg);
        byte[] out = new byte[argPadding.length];

        for(int i = 0; i < argPadding.length; i += 16){
            byte[] temp = new byte[16];
            int upper = i+16;
            for(int j = 0; j < 16; j++){
                temp[j] = argPadding[i+j];
            }
            byte[] oneBlockCrypted = encryptBlock(temp, keysExp);
            //System.out.println(new String(oneBlockCrypted));

            for(int j = i; j < upper; j++){
                out[j] = oneBlockCrypted[j-i];
            }
        }
        return out;
    }

    public static byte[] decryptECB(byte[] arg, byte[] key) {
        int[] keysExp = createKeyExpansion(key);
        byte[] bytes = arg;
        byte[] out = new byte[bytes.length];

        for(int i = 0; i < bytes.length; i += 16){
            byte[] temp = new byte[16];
            int upper = i+16;
            for(int j = 0; j < 16; j++){
                temp[j] = bytes[i+j];
            }
            byte[] oneBlockCrypted = decryptBlock(temp, keysExp);

            for(int j = i; j < upper; j++){
                out[j] = oneBlockCrypted[j-i];
            }
        }
        return out;
    }

    public static byte[] encryptCTR(byte[] bytes, byte[] key, byte[] iv) {
        int[] keysExp = createKeyExpansion(key);
        byte[] bytesPadding = addPadding(bytes);
        byte[] out = new byte[bytesPadding.length];

        long counter = 0L;
        byte[] inputToAES = new byte[16];

        for(int i = 0; i < iv.length; i++){
            inputToAES[i] = iv[i];
        }

        for(int i = 0; i < bytesPadding.length; i += 16){
            byte[] temp = new byte[16];
            int upper = i+16;
            for(int j = 0; j < 16; j++){
                temp[j] = bytesPadding[i+j];
            }
            byte [] counterBytes = longToBytes(counter);
            counter++;
            for(int k = iv.length; k < inputToAES.length; k++){
                inputToAES[k] = counterBytes[k - iv.length];
            }
            byte[] oneBlockCrypted = encryptBlock(inputToAES, keysExp);
            //System.out.println(new String(oneBlockCrypted));

            for(int j = i; j < upper; j++){
                out[j] = (byte) (oneBlockCrypted[j-i] ^ temp[j-i]);
            }
        }
        return out;
    }

    private static byte[] encryptBlock(byte[] input, int[] keysExp){
        byte[][] state = new byte[4][Nb];

        //System.out.println(keysExp.length);

        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                state[i][j] = input[i + 4*j];
            }
        }
        state = addRoundKey(state, keysExp, 0);
        //Krećem s rundama
        for(int round = 1; round < Nr; round++){
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, keysExp, round * Nb);
        }
        //bez mixCols
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, keysExp, Nr * Nb);

        byte[] out = new byte[16];
        for(int i = 0; i < 4; i++){
            for(int j = 0 ; j < 4; j++){
                out[i+4*j] = state[i][j];
            }
        }
        return out;
    }

    private static byte[] decryptBlock(byte[] input, int[] keysExp){
        byte[][] state = new byte[4][4];

        for(int i = 0; i < 4; i++){
            for(int j = 0; j < 4; j++){
                state[i][j] = input[i + 4*j];
            }
        }

        state = addRoundKey(state, keysExp, Nb * Nr);
        //krećem s rundama
        for(int round = Nr - 1; round > 0; round--){
            state = invShiftRows(state);
            state = invSubBytes(state);
            state = addRoundKey(state, keysExp, round*Nb);
            state = invMixColumns(state);
        }
        //bez mixCols
        state = invShiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, keysExp, 0);

        byte[] out = new byte[16];
        for(int i = 0; i < 4; i++){
            for(int j = 0 ; j < 4; j++){
                out[i+4*j] = state[i][j];
            }
        }
        return out;
    }

    private static byte[][] addRoundKey(byte[][] state, int[] keysExp, int i) {
        byte[][] outState = new byte[4][Nb];
        for (int c = 0; c < Nb; c++){
            //System.out.println(outState[0][c]);
            outState[0][c] = (byte) (byteAt(keysExp[i+c], 3) ^ state[0][c]);
            outState[1][c] = (byte) (byteAt(keysExp[i+c], 2) ^ state[1][c]);
            outState[2][c] = (byte) (byteAt(keysExp[i+c], 1) ^ state[2][c]);
            outState[3][c] = (byte) (byteAt(keysExp[i+c], 0) ^ state[3][c]);
        }
        return outState;
    }

    private static byte[][] mixColumns(byte[][] state) {
        byte[][] outState = new byte[state.length][state[0].length];
        for(int i = 0; i < Nb; i++){
            outState[0][i] = (byte) (multiplyGF(state[0][i], 0x02) ^ multiplyGF(state[1][i], 0x03) ^ state[2][i] ^ state[3][i]);
            //System.out.println(outState[0][i]);
            outState[1][i] = (byte) (state[0][i] ^ multiplyGF(state[1][i], 0x02) ^ multiplyGF(state[2][i], 0x03) ^ state[3][i]);
            outState[2][i] = (byte) (state[0][i] ^ state[1][i] ^ multiplyGF(state[2][i], 0x02) ^ multiplyGF(state[3][i], 0x03));
            outState[3][i] = (byte) (multiplyGF(state[0][i], 0x03) ^ state[1][i] ^ state[2][i] ^ multiplyGF(state[3][i], 0x02));
        }
        return outState;
    }

    private static byte[][] invMixColumns(byte[][] state) {
        byte[][] outState = new byte[state.length][state[0].length];
        for(int i = 0; i < Nb; i++){
            outState[0][i] = (byte) (multiplyGF(state[0][i], 0x0e) ^ multiplyGF(state[1][i], 0x0b) ^ multiplyGF(state[2][i], 0x0d) ^ multiplyGF(state[3][i], 0x09));
            //System.out.println(outState[0][i]);
            outState[1][i] = (byte) (multiplyGF(state[0][i], 0x09) ^ multiplyGF(state[1][i], 0x0e) ^ multiplyGF(state[2][i], 0x0b) ^ multiplyGF(state[3][i], 0x0d));
            outState[2][i] = (byte) (multiplyGF(state[0][i], 0x0d) ^ multiplyGF(state[1][i], 0x09) ^ multiplyGF(state[2][i], 0x0e) ^ multiplyGF(state[3][i], 0x0b));
            outState[3][i] = (byte) (multiplyGF(state[0][i], 0x0b) ^ multiplyGF(state[1][i], 0x0d) ^ multiplyGF(state[2][i], 0x09) ^ multiplyGF(state[3][i], 0x0e));
        }
        return outState;
    }

    private static byte[][] shiftRows(byte[][] state) {
        byte[][] outState = new byte[4][Nb];
        for(int i = 0; i < state.length; i++){
            for(int j = 0; j < state[i].length; j++){
                int jInd = (i+j) % Nb;
                //System.out.println(jInd);
                outState[i][j] = state[i][jInd];
            }
        }
        return outState;
    }

    private static byte[][] invShiftRows(byte[][] state) {
        byte[][] outState = new byte[4][Nb];
        for(int i = 0; i < state.length; i++){
            for(int j = 0; j < state[i].length; j++){
                int jInd = (i + j) % Nb;
                outState[i][jInd] = state[i][j];
            }
        }
        return outState;
    }

    private static byte[][] subBytes(byte[][] state) {
        for(int i = 0; i < state.length; i++){
            for (int j = 0; j < state[0].length; j++){
                state[i][j] = searchSBox(state[i][j]);
                //System.out.println(state[i][j]);
            }
        }
        return state;
    }

    private static byte[][] invSubBytes(byte[][] state) {
        for(int i = 0; i < state.length; i++){
            for (int j = 0; j < state[0].length; j++){
                state[i][j] = searchSBoxReverse(state[i][j]);
                //System.out.println(state[i][j]);
            }
        }
        return state;
    }

    private static byte multiplyGF(byte x, int y) {
        byte temp = 0;
        byte out = 0;
        while (x != 0) {
            if ((x & 1) != 0)
                out = (byte) (out ^ y);
            temp = (byte) (y & 0x80);
            y = (byte) (y << 1);
            if (temp != 0)
                y = (byte) (y ^ 0x1b);
            x = (byte) ((x & 0xff) >> 1);
        }
        return out;
    }

    private static byte searchSBox(byte b) {
        byte bLeast = (byte) (b & 0x0f);
        byte bMost = (byte) ((byte) (b >> 4) & 0x0f);

        byte out = sbox[bMost][bLeast];
        return out;
    }

    private static byte searchSBoxReverse(byte b) {
        byte bLeast = (byte) (b & 0x0f);
        byte bMost = (byte) ((byte) (b >> 4) & 0x0f);

        byte out = sboxInv[bMost][bLeast];
        return out;
    }

    private static byte byteAt(int val, int ind) {
        return (byte) ((val >>> (8 * ind)) & 0x000000ff);
    }

    private static void expandKey(byte[] key, int[] w) {
        int temp = 0;
        int i = 0;
        while (i < Nk) {
            w[i] = word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
            i++;
        }
        i = Nk;
        while (i < Nb * (Nr + 1)) {
            temp = w[i - 1];
            if (i % Nk == 0) {
                temp = subWord(rotate(temp)) ^ rcon[i / Nk];
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
            w[i] = w[i - Nk] ^ temp;
            i++;
        }
    }

    public static int[] createKeyExpansion(byte[] key) {
        int w[] = new int[Nb * (Nr + 1)];
        expandKey(key, w);
        return w;
    }

    private static int subWord(int word) {
        int intOut = 0;

        intOut ^= (int) searchSBox((byte) (word >>> 24)) & 0x000000ff;
        intOut <<= 8;
        intOut ^= (int) searchSBox((byte) ((0xff0000 & word) >>> 16)) & 0x000000ff;
        intOut <<= 8;
        intOut ^= (int) searchSBox((byte) ((0xff00 & word) >>> 8)) & 0x000000ff;
        intOut <<= 8;
        intOut ^= (int) searchSBox((byte) (0xff & word )) & 0x000000ff;

        return intOut;
    }

    private static byte[] addPadding(byte[] arg) {
        int wantedLen = (int) Math.ceil(arg.length / 16.0) * 16;
        int realLen = arg.length;
        byte [] toByte = arg;
        byte [] out = new byte[wantedLen];

        for(int i = 0; i < toByte.length; i++){
            out[i] = toByte[i];
        }
        boolean first = true;
        while(realLen != wantedLen){
            if(first){
                out[realLen] = (byte)0x80;
                //System.out.println("Dodao prvi");
                first = false;
            }
            else{
                //System.out.println("Dodao drugi");
                out[realLen] = (byte)0x00;

            }
            realLen++;
        }
        return out;
    }

    //long u byte array
    private static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    private static int rotate(int word) {
        int out = (word << 8) ^ ((word >> 24) & 0x000000ff);
        return out;
    }

    private static int word(byte b1, byte b2, byte b3, byte b4) {
        int word = 0;

        word ^= ((int) b1) << 24;
        word ^= (((int) b2) & 0x000000ff) << 16;
        word ^= (((int) b3) & 0x000000ff) << 8;
        word ^= (((int) b4) & 0x000000ff);

        return word;
    }
}
