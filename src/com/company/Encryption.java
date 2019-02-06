/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.company;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

/**
 * @author Abdulsalam Mansour
 */
class Encryption {

    private final String adminKey = "TheWorldGovernment";
    private int[] adminKeyValues;
    private String plainKey;
    private String path;
    private int keyValues[];
    private int vpKeyValues[];
    private int[][] vigenere;
    private boolean singleStamp = true;


    Encryption(String plainKey, String path) {
        this.plainKey = plainKey;
        this.path = path;

        vigenere = generateVigenere();
        vpKeyValues = getVpKeyValues(plainKey);
        keyValues = getKeyValues(plainKey);
        adminKeyValues = getKeyValues(adminKey);
    }


    private int[] getKeyValues(String key) {
        char[] charKey = key.toCharArray();
        int[] intKey = new int[charKey.length];

        for (int i = 0; i < intKey.length; i++) {

            intKey[i] = (int) charKey[i];

        }


        return intKey;


    }

    // Wrapper Methods


    private void wrapper() {

        //adds 1 kb stamp to the file
        //bytes from 0 to 999 are key plain text
        //bytes from 1000 to 1018 are extension plain text
        //byte 1019 is extension length
        //bytes 1020 to 1023 are key length


        try {
            RandomAccessFile out = new RandomAccessFile(path, "rwd");


            byte[] bytesExtension = Objects.requireNonNull(getExtension(path)).getBytes();
            byte extensionLength = (byte) bytesExtension.length;
            byte[] bytesKey = stringToBytes(plainKey);
            byte[] keyLength = intToBytes(plainKey.length());

            byte[] stamp = new byte[1024];


            //loop to fill the key in the stamp array

            assert bytesKey != null;
            System.arraycopy(bytesKey, 0, stamp, 0, bytesKey.length);


            //loop to fill key length into the stamp array

            int outerCounter = 0;
            for (int i = 1020; i < 1024; i++) {
                stamp[i] = keyLength[outerCounter];
                outerCounter++;
            }


            //loop to fill extension into the stamp array

            outerCounter = 1000;

            for (byte aBytesExtension : bytesExtension) {

                stamp[outerCounter] = aBytesExtension;
                outerCounter++;
            }

            stamp[1019] = extensionLength;


            //Encrypt the stamp KB

            ArrayList<Integer> listStamp = arrayToList(stamp);
            listStamp = manhattanCipherEncryptLite(listStamp);
            stamp = listToArray(listStamp);


            out.seek(out.length());
            out.write(stamp);

            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }


    private String[] unwrapper() {

        byte[] rawBytes = new byte[1024];
        byte[] rawKey = new byte[1000];
        byte[] rawExtension = new byte[19];
        byte[] keyLength = new byte[4];
        byte extensionLength;
        int keySize;
        int extensionSize;

        String[] returnValues = new String[2];


        try {
            RandomAccessFile in = new RandomAccessFile(path, "rwd");


            in.seek(in.length() - 1024);
            in.read(rawBytes);


            //decrypt the stamp

            ArrayList<Integer> listStamp = arrayToList(rawBytes);
            listStamp = manhattanCipherDecryptLite(listStamp);
            rawBytes = listToArray(listStamp);


            //loop to get the key
            System.arraycopy(rawBytes, 0, rawKey, 0, 1000);


            //loop to get the key length
            int index = 0;

            for (int i = 1020; i < rawBytes.length; i++) {
                keyLength[index] = rawBytes[i];

                index++;
            }

            //loop to get the extension
            index = 0;

            for (int i = 1000; i < 1019; i++) {

                rawExtension[index] = rawBytes[i];
                index++;
            }

            extensionLength = rawBytes[1019];


            keySize = bytesToInt(keyLength);
            returnValues[0] = bytesToString(rawKey, keySize);
            extensionSize = extensionLength & 0xFF;
            returnValues[1] = bytesToString(rawExtension, extensionSize);


            in.close();


        } catch (IOException e) {
            e.printStackTrace();
        }

        //String newPath = stitchExtension(path,returnValues[1]);

        //replacePath(path,newPath);

        return returnValues;
    }


    private byte[] intToBytes(int number) {

        return ByteBuffer.allocate(4).putInt(number).array();
    }

    private int bytesToInt(byte[] bytes) {
        return bytes[0] << 24 | (bytes[1] & 0xFF) << 16 | (bytes[2] & 0xFF) << 8 | (bytes[3] & 0xFF);
    }


    private byte[] stringToBytes(String key) {
        byte[] tmp = key.getBytes();


        int bound = tmp.length;

        if (bound < 1020) {
            byte[] keyBytes = new byte[1020];

            System.arraycopy(tmp, 0, keyBytes, 0, bound);


            for (int i = bound; i < 1020; i++) {

                keyBytes[i] = (byte) ThreadLocalRandom.current().nextInt(0, 255 + 1);
            }

            return keyBytes;
        } else if (bound == 1020)
            return tmp;

        else
            return null;

    }


    private String bytesToString(byte[] rawKey, int length) {


        byte[] realkey = new byte[length];

        System.arraycopy(rawKey, 0, realkey, 0, length);


        return new String(realkey);


    }


    private void trimmer(String path) {


        long length;
        try {
            RandomAccessFile file = new RandomAccessFile(path, "rwd");
            length = file.length();

            file.setLength(length - 1024);

            file.close();

        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    private byte[] listToArray(ArrayList<Integer> stampList) {
        byte[] stamp = new byte[1024];

        for (int i = 0; i < stamp.length; i++) {

            stamp[i] = (byte) ((int) stampList.get(i));
        }

        return stamp;
    }


    private ArrayList<Integer> arrayToList(byte[] stamp) {
        ArrayList<Integer> stampList = new ArrayList<>();

        for (byte aStamp : stamp) {
            stampList.add(aStamp & 0xFF);
        }

        return stampList;
    }


    private String getExtension(String path) {

        String extension;
        int i = path.lastIndexOf('.');
        if (i > 0) {
            extension = path.substring(i + 1);

            return extension;

        } else {
            return null;
        }


    }


    private String stitchExtension(String path, String extension) {
        int i = path.lastIndexOf('.');
        if (i > 0) {

            StringBuilder newPath = new StringBuilder(path);
            for (int j = path.lastIndexOf('.'); j < path.length(); j++) {
                newPath.deleteCharAt(i);
            }

            newPath.append(".");
            newPath.append(extension);

            return newPath.toString();

        } else {
            return null;
        }

    }


    private void replacePath(String oldPath, String newPath) {

        byte[] buffer = new byte[104857600];

        int bytesRead;


        try {
            FileInputStream in = new FileInputStream(oldPath);
            FileOutputStream out = new FileOutputStream(newPath);

            while ((bytesRead = in.read(buffer)) != -1) {

                out.write(buffer, 0, bytesRead);
            }


            in.close();
            out.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

        File file = new File(oldPath);

        file.delete();


    }


    String recoverKey(String superKey) {

        if (superKey.equals(adminKey)) {
            String[] returnValue;
            returnValue = unwrapper();
            return returnValue[0];
        } else {
            return null;
        }


    }


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //Manhattan Cipher

    void manhattanCipherEncrypt() {

        singleStamp = false;

        int sequence = generateManhattanSequence();

        switch (sequence) {

            case 0:
                // C V P
                caeserCipherEncrypt();
                vigenereCipherEncrypt();
                vectorOfPermutationEncrypt();

                break;


            case 1:
                // C P V
                caeserCipherEncrypt();
                vectorOfPermutationEncrypt();
                vigenereCipherEncrypt();
                break;


            case 2:
                // V C P
                vigenereCipherEncrypt();
                caeserCipherEncrypt();
                vectorOfPermutationEncrypt();
                break;


            case 3:
                // V P C
                vigenereCipherEncrypt();
                vectorOfPermutationEncrypt();
                caeserCipherEncrypt();
                break;

            case 4:
                // P C V
                vectorOfPermutationEncrypt();
                caeserCipherEncrypt();
                vigenereCipherEncrypt();
                break;

            case 5:
                // P V C
                vectorOfPermutationEncrypt();
                vigenereCipherEncrypt();
                caeserCipherEncrypt();
                break;


        }


        wrapper();
        String encPath = stitchExtension(path, "enc");
        replacePath(path, encPath);
        singleStamp = true;

    }


    void manhattanCipherDecrypt() {

        int sequence = generateManhattanSequence();

        singleStamp = false;


        String[] retrievedData;

        retrievedData = unwrapper();
        trimmer(path);
        String realPath = stitchExtension(path, retrievedData[1]);
        replacePath(path, realPath);
        path = realPath;


        switch (sequence) {

            case 0:
                // C V P
                vectorOfPermutationDecrypt();
                vigenereCipherDecrypt();
                caeserCipherDecrypt();
                break;

            case 1:
                // C P V
                vigenereCipherDecrypt();
                vectorOfPermutationDecrypt();
                caeserCipherDecrypt();
                break;

            case 2:
                // V C P
                vectorOfPermutationDecrypt();
                caeserCipherDecrypt();
                vigenereCipherDecrypt();
                break;

            case 3:
                // V P C
                caeserCipherDecrypt();
                vectorOfPermutationDecrypt();
                vigenereCipherDecrypt();
                break;

            case 4:
                // P C V
                vigenereCipherDecrypt();
                caeserCipherDecrypt();
                vectorOfPermutationDecrypt();
                break;

            case 5:
                // P V C
                caeserCipherDecrypt();
                vigenereCipherDecrypt();
                vectorOfPermutationDecrypt();
                break;

        }

        singleStamp = true;

    }


    private int generateManhattanSequence() {

        int keySum = 0;


        for (int keyValue : keyValues) {
            keySum = keySum + keyValue;
        }

        return keySum % 6;
    }


    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //Caeser Cipher

    void caeserCipherEncrypt() {


        int index = 0;
        int ci;
        long pos = 0;
        int bytesRead;
        byte[] buffer = new byte[1048576];      //buffer that can hold 1 MB

        int[] unsignedBytesBuffer = new int[1048576];


        try {
            RandomAccessFile plainText = new RandomAccessFile(path, "rw");


            plainText.seek(0); // Move the file pointer to the first byte in the file;


            while ((bytesRead = plainText.read(buffer)) != -1) {

                pos += bytesRead;


                // loop for converting the data in buffer from signed byte to unsigned byte.
                for (int i = 0; i < bytesRead; i++) {


                    unsignedBytesBuffer[i] = (buffer[i]) & 0xFF;

                }

                // loop for encrypting the data in the buffer

                for (int i = 0; i < bytesRead; i++) {

                    ci = unsignedBytesBuffer[i];
                    ci = (ci + keyValues[index]) % 256;

                    unsignedBytesBuffer[i] = ci;

                    index = (++index) % keyValues.length;

                }

                // loop for converting unsigned bytes to signed bytes

                for (int i = 0; i < bytesRead; i++) {


                    buffer[i] = (byte) unsignedBytesBuffer[i];

                }

                plainText.seek(pos - bytesRead);
                plainText.write(buffer, 0, bytesRead);


            }


            plainText.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

        if (singleStamp) {
            wrapper();
            String encPath = stitchExtension(path, "enc");
            replacePath(path, encPath);
        }
    }

    void caeserCipherDecrypt() {

        String[] retrievedData;
        if (singleStamp) {
            retrievedData = unwrapper();
            trimmer(path);
            String realPath = stitchExtension(path, retrievedData[1]);
            replacePath(path, realPath);
            path = realPath;
        }


        int index = 0;
        int ci;
        long pos = 0;
        int bytesRead;
        byte[] buffer = new byte[1048576];      //buffer that can hold 1 MB

        int[] unsignedBytesBuffer = new int[1048576];


        try {
            RandomAccessFile plainText = new RandomAccessFile(path, "rw");


            plainText.seek(0); // Move the file pointer to the first byte in the file;


            while ((bytesRead = plainText.read(buffer)) != -1) {

                pos += bytesRead;


                // loop for converting the data in buffer from signed byte to unsigned byte.
                for (int i = 0; i < bytesRead; i++) {


                    unsignedBytesBuffer[i] = (buffer[i]) & 0xFF;

                }

                // loop for encrypting the data in the buffer

                for (int i = 0; i < bytesRead; i++) {

                    ci = unsignedBytesBuffer[i];

                    ci = (ci - keyValues[index] + 256) % 256;

                    unsignedBytesBuffer[i] = ci;

                    index = (++index) % keyValues.length;

                }

                // loop for converting unsigned bytes to signed bytes

                for (int i = 0; i < bytesRead; i++) {


                    buffer[i] = (byte) unsignedBytesBuffer[i];

                }

                plainText.seek(pos - bytesRead);
                plainText.write(buffer, 0, bytesRead);


            }


            plainText.seek(0);

            plainText.close();

        } catch (IOException e) {
            e.printStackTrace();
        }


    }


    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //vigenere Cipher

    void vigenereCipherEncrypt() {


        int rowIndex;
        int columnIndex;

        int index = 0;
        int ci;
        long pos = 0;
        int bytesRead;
        byte[] buffer = new byte[1048576];      //buffer that can hold 1 MB

        int[] unsignedBytesBuffer = new int[1048576];


        try {
            RandomAccessFile plainText = new RandomAccessFile(path, "rw");
            plainText.seek(0); // Move the file pointer to the first byte in the file;


            while ((bytesRead = plainText.read(buffer)) != -1) {

                pos += bytesRead;


                // loop for converting the data in buffer from signed byte to unsigned byte.
                for (int i = 0; i < bytesRead; i++) {


                    unsignedBytesBuffer[i] = (buffer[i]) & 0xFF;

                }

                // loop for encrypting the data in the buffer

                for (int i = 0; i < bytesRead; i++) {

                    rowIndex = unsignedBytesBuffer[i];
                    columnIndex = keyValues[index];

                    ci = vigenere[rowIndex][columnIndex];
                    unsignedBytesBuffer[i] = ci;


                    index = (++index) % keyValues.length;

                }

                // loop for converting unsigned bytes to signed bytes

                for (int i = 0; i < bytesRead; i++) {


                    buffer[i] = (byte) unsignedBytesBuffer[i];

                }

                plainText.seek(pos - bytesRead);
                plainText.write(buffer, 0, bytesRead);


            }


            plainText.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

        if (singleStamp) {
            wrapper();
            String encPath = stitchExtension(path, "enc");
            replacePath(path, encPath);
        }


    }


    void vigenereCipherDecrypt() {


        String[] retrievedData;
        if (singleStamp) {
            retrievedData = unwrapper();
            trimmer(path);
            String realPath = stitchExtension(path, retrievedData[1]);
            replacePath(path, realPath);
            path = realPath;
        }

        int index = 0;


        int rowIndex;
        int columnIndex;


        int pi;
        long pos = 0;
        int bytesRead;
        byte[] buffer = new byte[1048576];      //buffer that can hold 1 MB

        int[] unsignedBytesBuffer = new int[1048576];


        try {
            RandomAccessFile plainText = new RandomAccessFile(path, "rw");


            plainText.seek(0); // Move the file pointer to the first byte in the file;


            while ((bytesRead = plainText.read(buffer)) != -1) {

                pos += bytesRead;


                // loop for converting the data in buffer from signed byte to unsigned byte.
                for (int i = 0; i < bytesRead; i++) {


                    unsignedBytesBuffer[i] = (buffer[i]) & 0xFF;

                }

                // loop for Decrypting the data in the buffer


                for (int i = 0; i < bytesRead; i++) {
                    rowIndex = unsignedBytesBuffer[i];
                    columnIndex = keyValues[index];

                    pi = vigenere[rowIndex][columnIndex];
                    unsignedBytesBuffer[i] = pi;


                    index = (++index) % keyValues.length;


                }

                // loop for converting unsigned bytes to signed bytes

                for (int i = 0; i < bytesRead; i++) {


                    buffer[i] = (byte) unsignedBytesBuffer[i];

                }

                plainText.seek(pos - bytesRead);
                plainText.write(buffer, 0, bytesRead);


            }


            plainText.seek(0);

            plainText.close();

        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    private static int[][] generateVigenere() {


        int[][] vigenereMatrix = new int[256][256];

        ArrayList<Integer> inner = new ArrayList<>();

        for (int i = 0; i < 256; i++) {

            inner.add(i);


        }

        ArrayList<ArrayList> vigenereList = new ArrayList<>();

        for (int i = 0; i < 256; i++) {

            vigenereList.add(new ArrayList<>(inner));

            rotateList(inner);


        }


        for (int i = 0; i < 256; i++) {

            for (int j = 0; j < 256; j++) {

                vigenereMatrix[i][j] = (Integer) vigenereList.get(i).get(j);


            }
        }


        return vigenereMatrix;


    }

    private static void rotateList(ArrayList<Integer> list) {

        int tmp = list.remove(list.size() - 1);
        list.add(0, tmp);
    }


    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //Vector Of Permutation Cipher

    void vectorOfPermutationEncrypt() {


        int innerCounter;
        int vpCounter;


        int bufferLength = generateBufferLength(vpKeyValues.length);

        byte[] buffer = new byte[bufferLength];
        int[] unsignedBytesBuffer = new int[bufferLength];

        int[] plainTextBlock = new int[vpKeyValues.length];

        int[][] vp = new int[vpKeyValues.length][vpKeyValues.length];

        int numberOfBlocks;

        long pos = 0;
        int bytesReadRaw;
        int bytesRead;
        int bytesRemainder;

        boolean blockLengthException = false;


        try {
            RandomAccessFile plainText = new RandomAccessFile(path, "rw");


            // Main loop
            while ((bytesReadRaw = plainText.read(buffer)) != -1) {

                bytesRead = bytesReadRaw;
                pos += bytesReadRaw;

                //condition to determine if the buffer contains bytes that can't form a cipher block
                if ((bytesRemainder = bytesRead % plainTextBlock.length) != 0) {
                    bytesRead = bytesRead - bytesRemainder;
                    blockLengthException = true;
                }


                // loop for converting the data in buffer from signed byte to unsigned byte.

                for (int i = 0; i < bytesRead; i++) {


                    unsignedBytesBuffer[i] = (buffer[i]) & 0xFF;

                }


                numberOfBlocks = bytesRead / plainTextBlock.length;

                innerCounter = 0;

                //loop for reading all the blocks in the buffer and for encrypting the data in the buffer

                for (int i = 0; i < numberOfBlocks; i++) {


                    //loop for reading a block of plaintext from buffer

                    for (int j = 0; j < plainTextBlock.length; j++) {

                        plainTextBlock[j] = buffer[innerCounter];
                        innerCounter++;
                    }

                    vectorOfPermutationBlockEncrypt(vp, vpKeyValues, plainTextBlock);


                    vpCounter = 0;

                    //loop for writing the block of encrypted data to buffer

                    for (int j = innerCounter - plainTextBlock.length; j < innerCounter; j++) {
                        unsignedBytesBuffer[j] = vp[plainTextBlock.length - 1][vpCounter];
                        vpCounter++;

                    }


                }

                // loop for converting unsigned bytes to signed bytes

                for (int i = 0; i < bytesRead; i++) {


                    buffer[i] = (byte) unsignedBytesBuffer[i];

                }


                //block for writing encrypted data on the file


                plainText.seek(pos - bytesReadRaw);
                plainText.write(buffer, 0, bytesRead);


                if (blockLengthException)
                    break;


            }


            //condition for handling the case in which there is extra bytes

            if (blockLengthException) {


                //loop for reading the last bytes from the file, the data is placed in the last cells of the PlainTextBlock

                pos = plainText.length() - 1;
                for (int i = 0; i < plainTextBlock.length; i++) {
                    plainText.seek(--pos);
                    plainTextBlock[plainTextBlock.length - 1 - i] = plainText.read();

                }

                vectorOfPermutationBlockEncrypt(vp, vpKeyValues, plainTextBlock);


                plainText.seek(pos);

                for (int i = 0; i < plainTextBlock.length; i++) {

                    plainText.write(vp[plainTextBlock.length - 1][i]);
                }

            }


            plainText.close();

        } catch (IOException e) {
            e.printStackTrace();
        }


        if (singleStamp) {
            wrapper();
            String encPath = stitchExtension(path, "enc");
            replacePath(path, encPath);
        }


    }

    private void vectorOfPermutationBlockEncrypt(int[][] vp, int[] keyValues, int[] plainText) {


        swap(plainText, 0, keyValues[0]);


        System.arraycopy(plainText, 0, vp[0], 0, keyValues.length);

        for (int i = 1; i < keyValues.length; i++) {

            System.arraycopy(vp[i - 1], 0, vp[i], 0, keyValues.length);

            swap2D(vp, i, i, keyValues[i]);
        }


    }

    void vectorOfPermutationDecrypt() {

        String[] retrievedData;
        if (singleStamp) {
            retrievedData = unwrapper();
            trimmer(path);
            String realPath = stitchExtension(path, retrievedData[1]);
            replacePath(path, realPath);
            path = realPath;
        }


        int innerCounter;
        int vpCounter;


        int bufferLength = generateBufferLength(vpKeyValues.length);

        byte[] buffer = new byte[bufferLength];
        int[] unsignedBytesBuffer = new int[bufferLength];

        int[] cipherTextBlock = new int[vpKeyValues.length];

        int[][] vp = new int[vpKeyValues.length][vpKeyValues.length];

        int numberOfBlocks;


        long pos = 0;
        int bytesReadRaw;
        int bytesRead;
        int bytesRemainder = 0;

        boolean blockLengthException = false;

        try {
            RandomAccessFile cipher = new RandomAccessFile(path, "rw");


            // Main loop
            while ((bytesReadRaw = cipher.read(buffer)) != -1) {

                bytesRead = bytesReadRaw;
                pos += bytesReadRaw;

                //condition to determine if the buffer contains bytes that can't form a cipher block
                if ((bytesRemainder = bytesRead % cipherTextBlock.length) != 0) {
                    bytesRead = bytesRead - bytesRemainder;
                    blockLengthException = true;
                }


                // loop for converting the data in buffer from signed byte to unsigned byte.

                for (int i = 0; i < bytesRead; i++) {


                    unsignedBytesBuffer[i] = (buffer[i]) & 0xFF;

                }


                numberOfBlocks = bytesRead / cipherTextBlock.length;

                if (blockLengthException)
                    numberOfBlocks--;

                innerCounter = 0;

                //loop for reading all the blocks in the buffer and for decrypting the data in the buffer

                for (int i = 0; i < numberOfBlocks; i++) {


                    //loop for reading a block of plaintext from buffer

                    for (int j = 0; j < cipherTextBlock.length; j++) {

                        cipherTextBlock[j] = buffer[innerCounter];
                        innerCounter++;
                    }

                    vectorOfPermutationBlockDecrypt(vp, vpKeyValues, cipherTextBlock);


                    vpCounter = 0;

                    //loop for writing the block of encrypted data to buffer

                    for (int j = innerCounter - cipherTextBlock.length; j < innerCounter; j++) {
                        unsignedBytesBuffer[j] = vp[cipherTextBlock.length - 1][vpCounter];
                        vpCounter++;

                    }


                }

                // loop for converting unsigned bytes to signed bytes

                for (int i = 0; i < bytesRead; i++) {


                    buffer[i] = (byte) unsignedBytesBuffer[i];

                }


                //block for writing encrypted data on the file


                cipher.seek(pos - bytesReadRaw);
                cipher.write(buffer, 0, bytesRead);


                if (blockLengthException)
                    break;


            }


            //condition for handling the case in which there is extra bytes

            if (blockLengthException) {


                //loop for reading the last bytes from the file, the data is placed in the last cells of the cipherTextBlock

                pos = cipher.length() - 1;
                for (int i = 0; i < cipherTextBlock.length; i++) {
                    cipher.seek(--pos);
                    cipherTextBlock[cipherTextBlock.length - 1 - i] = cipher.read();

                }

                vectorOfPermutationBlockDecrypt(vp, vpKeyValues, cipherTextBlock);


                cipher.seek(pos);

                for (int i = 0; i < cipherTextBlock.length; i++) {

                    cipher.write(vp[cipherTextBlock.length - 1][i]);
                }

                //now we decrypt the last whole block

                pos = cipher.length() - 1 - bytesRemainder - cipherTextBlock.length;

                cipher.seek(pos);


                for (int i = 0; i < cipherTextBlock.length; i++) {

                    cipherTextBlock[i] = cipher.read();

                }

                vectorOfPermutationBlockDecrypt(vp, vpKeyValues, cipherTextBlock);

                cipher.seek(pos);


                for (int i = 0; i < cipherTextBlock.length; i++) {

                    cipher.write(vp[cipherTextBlock.length - 1][i]);

                }

            }


            cipher.close();

        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    private void vectorOfPermutationBlockDecrypt(int[][] vp, int[] keyValues, int[] cipher) {


        swap(cipher, keyValues.length - 1, keyValues[keyValues.length - 1]);


        System.arraycopy(cipher, 0, vp[0], 0, keyValues.length);


        int innerCount = 1;
        for (int i = keyValues.length - 2; i >= 0; i--) {

            System.arraycopy(vp[innerCount - 1], 0, vp[innerCount], 0, keyValues.length);

            swap2D(vp, innerCount, i, keyValues[i]);

            innerCount++;
        }


    }


    private void swap2D(int[][] vp, int rowIndex, int item1, int item2) {

        int tmp;

        tmp = vp[rowIndex][item1];

        vp[rowIndex][item1] = vp[rowIndex][item2];

        vp[rowIndex][item2] = tmp;


    }

    private void swap(int[] array, int i, int j) {
        int temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }


    private int generateBufferLength(int keyLength) {

        int index = 0;
        int factor = 1000000;


        while (true) {

            if ((index < keyLength) && ((index = index + 10) >= keyLength))
                return (keyLength * factor);


            factor = factor / 2;


        }
    }

    private int[] getVpKeyValues(String key) {
        char[] charKey = key.toCharArray();
        int[] intKey = new int[charKey.length];

        for (int i = 0; i < intKey.length; i++) {

            intKey[i] = (int) charKey[i];

        }

        for (int i = 0; i < intKey.length; i++) {

            intKey[i] = intKey[i] % intKey.length;

        }


        return intKey;


    }


    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    //stamp encryption methods

    private ArrayList<Integer> manhattanCipherEncryptLite(ArrayList<Integer> plainText) {


        caeserCipherEncryptLite(plainText);
        vigenereCipherEncryptLite(plainText);
        //list = vectorOfPermutationEncryptLite(plainText,vpKeyValues);


        return plainText;

    }

    private ArrayList<Integer> manhattanCipherDecryptLite(ArrayList<Integer> cipher) {

        //list = vectorOfPermutationDecryptLite(cipher,vpKeyValues);
        vigenereCipherDecryptLite(cipher);
        caeserCipherDecryptLite(cipher);


        return cipher;

    }

//----------------------------------------------------------------------------------------------------------------------
    //caeser methods

    private void caeserCipherEncryptLite(ArrayList<Integer> plainText) {


        int index = 0;
        int ci;

        for (int i = 0; i < plainText.size(); i++) {

            ci = plainText.get(i);
            ci = (ci + adminKeyValues[index]) % 256;

            plainText.set(i, ci);

            index = (++index) % adminKeyValues.length;


        }


    }

    private void caeserCipherDecryptLite(ArrayList<Integer> cipher) {


        int index = 0;
        int pi;

        for (int i = 0; i < cipher.size(); i++) {

            pi = cipher.get(i);
            pi = (pi - adminKeyValues[index] + 256) % 256;


            cipher.set(i, pi);

            index = (++index) % adminKeyValues.length;


        }

    }

    //------------------------------------------------------------------------------------------------------------------
    //Vigenere Methods


    private void vigenereCipherEncryptLite(ArrayList<Integer> plainText) {


        int index = 0;

        int ci;
        int rowIndex;
        int columnIndex;

        for (int i = 0; i < plainText.size(); i++) {

            rowIndex = plainText.get(i);
            columnIndex = adminKeyValues[index];

            ci = vigenere[rowIndex][columnIndex];

            plainText.set(i, ci);

            index = (++index) % adminKeyValues.length;


        }

        //return cipher;
    }


    private void vigenereCipherDecryptLite(ArrayList<Integer> cipher) {

        int[][] vigenere = generateVigenere();

        int index = 0;


        int pi;
        int rowIndex;
        int columnIndex;

        for (int i = 0; i < cipher.size(); i++) {

            rowIndex = cipher.get(i);
            columnIndex = adminKeyValues[index];

            pi = vigenere[rowIndex][columnIndex];

            cipher.set(i, pi);

            index = (++index) % adminKeyValues.length;


        }

    }


}

