package com.hashengineering.crypto;

import fr.cryptohash.Groestl512;
import org.bouncycastle.crypto.Digest;


/**
 * Created by Hash Engineering on 12/24/14 for the Groestl algorithm
 */
public class Groestl implements Digest {


    private static boolean native_library_loaded;
    final Groestl512 digestGroestl = new Groestl512();

    static {

        try {
            System.loadLibrary("groestld");
            native_library_loaded = true;
        } catch(UnsatisfiedLinkError | Exception x) {
            native_library_loaded = false;
        }
    }

    public byte[] digest(byte[] input, int offset, int length)
    {
        try {
            return native_library_loaded ? groestld_native(input, offset, length) : groestl(input, offset, length);
        } catch (Exception e) {
            return groestl(input, offset, length);
        }
    }

    public byte[] digest(byte[] input) {
        try {
            return native_library_loaded ? groestld_native(input, 0, input.length) : groestl(input);
        } catch (Exception e) {
            return groestl(input);
        }
    }

    static native byte [] groestld_native(byte [] input, int offset, int len);

    byte [] groestl(byte header[]) {
        Groestl512 hasher1 = new Groestl512();
        Groestl512 hasher2 = new Groestl512();

        byte [] hash1 = hasher1.digest(header);
        byte [] hash2 = hasher2.digest(hash1);

        byte [] result = new byte[32];

        System.arraycopy(hash2, 0, result, 0, 32);
        return result;
    }

    byte [] groestl(byte header[], int offset, int length) {
        digestGroestl.reset();
        digestGroestl.update(header, offset, length);
        byte [] hash512 = digestGroestl.digest();
        byte [] hash512_2 = digestGroestl.digest(hash512);

        byte [] result = new byte[32];
        System.arraycopy(hash512_2, 0, result, 0, 32);
        return result;
    }

    @Override
    public void reset() {
        digestGroestl.reset();
    }

    @Override
    public String getAlgorithmName() {
        return "groestl-2x";
    }

    @Override
    public void update(byte[] bytes, int i, int i1) {
        digestGroestl.update(bytes, i, i1);
    }

    @Override
    public void update(byte b) {
        digestGroestl.update(b);
    }

    @Override
    public int getDigestSize() {
        return 32;
    }

    @Override
    public int doFinal(byte[] bytes, int i) {
        byte [] hash512 = digestGroestl.digest();
        System.arraycopy(hash512, 0, bytes, 0, 32);
        return bytes.length;
    }
}
