package com.hashengineering.crypto;

import fr.cryptohash.Groestl512;
import org.spongycastle.crypto.Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Hash Engineering on 12/24/14 for the Groestl algorithm
 */
public class Groestl implements Digest {


    private static boolean native_library_loaded = false;
    private static final Groestl512 digestGroestl = new Groestl512();

    static {

        try {
            System.loadLibrary("groestld");
            native_library_loaded = true;
        }
        catch(UnsatisfiedLinkError x)
        {
            native_library_loaded = false;
        }
        catch(Exception e)
        {
            native_library_loaded = false;
        }
    }

    public static byte[] digest(byte[] input, int offset, int length)
    {
        try {
            return native_library_loaded ? groestld_native(input, offset, length) : groestl(input, offset, length);
        } catch (Exception e) {
            return null;
        }
        finally {
        }
    }

    public static byte[] digest(byte[] input) {
        try {
            return native_library_loaded ? groestld_native(input, 0, input.length) : groestl(input);
        } catch (Exception e) {
            return null;
        }
        finally {
        }

    }

    static native byte [] groestld_native(byte [] input, int offset, int len);

    static byte [] groestl(byte header[])
    {
        //digestGroestl.reset();
        //byte [] hash512 = digestGroestl.digest(header);
        //digestGroestl.reset();
        //byte [] doubleHash512 = digestGroestl.digest(hash512);
        //Initialize
        //return new Sha512Hash(doubleHash512).trim256().getBytes();

        Groestl512 hasher1 = new Groestl512();
        Groestl512 hasher2 = new Groestl512();

        /*digestGroestl.reset();
        byte [] hash512 = digestGroestl.digest(header);
        //digestGroestl.reset();
        byte [] doubleHash512 = digestGroestl.digest(hash512);
        //Initialize
        return new Sha512Hash(doubleHash512).trim256().getBytes();
        */
        byte [] hash1 = hasher1.digest(header);
        byte [] hash2 = hasher2.digest(hash1);

        byte [] result = new byte[32];

        for (int i = 0; i < 32; i++){
             result[i] = hash2[i];
        }
        return result;

    }

    static byte [] groestl(byte header[], int offset, int length)
    {
        digestGroestl.reset();
        digestGroestl.update(header, offset, length);
        byte [] hash512 = digestGroestl.digest();

        //digestGroestl.update(hash512);
        byte [] hash512_2 = digestGroestl.digest(hash512);
        //Initialize

        byte [] result = new byte[32];

        for (int i = 0; i < 32; i++){
            result[i] = hash512_2[i];
        }
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
        return 0;
    }
}
