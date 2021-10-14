package io.tus.java.client;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is used for doing the actual upload of the files. Instances are returned by
 * {@link TusClient#createUpload(TusUpload)}, {@link TusClient#createUpload(TusUpload)} and
 * {@link TusClient#resumeOrCreateUpload(TusUpload)}.
 * <br>
 * After obtaining an instance you can upload a file by following these steps:
 * <ol>
 *  <li>Upload a chunk using {@link #uploadChunk(Map<String, String>)}</li>
 *  <li>Optionally get the new offset ({@link #getOffset()} to calculate the progress</li>
 *  <li>Repeat step 1 until the {@link #uploadChunk(Map<String, String>)} returns -1</li>
 *  <li>Close HTTP connection and InputStream using {@link #finish()} to free resources</li>
 * </ol>
 */
public class TusUploader {
    private URL uploadURL;
    private TusInputStream input;
    private long offset;
    private TusClient client;
    private TusUpload upload;
    private byte[] buffer;
    private int requestPayloadSize = 5 * 1024 * 1024;
    private int bytesRemainingForRequest;

    private HttpURLConnection connection;
    private OutputStream output;

    //encrytion varaibles
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;
    public static final String ALGO = "AES/CTR/NoPadding";

    private static String key = "RE8wcS4wMnBATlpnVGIzMjFrVnhqMiwuNUMkLGRCWXo=";
    //    private static final byte[] IV = "1234567890123456".getBytes();
    private static String IV = "MTIzNDU2Nzg5MDEyMzQ1Ng==";
    KeyGenerator keyGenerator = null;

    /**
     * Begin a new upload request by opening a PATCH request to specified upload URL. After this
     * method returns a connection will be ready and you can upload chunks of the file.
     *
     * @param client    Used for preparing a request ({@link TusClient#prepareConnection(HttpURLConnection)}
     * @param uploadURL URL to send the request to
     * @param input     Stream to read (and seek) from and upload to the remote server
     * @param offset    Offset to read from
     * @throws IOException Thrown if an exception occurs while issuing the HTTP request.
     */
    public TusUploader(TusClient client, TusUpload upload, URL uploadURL, TusInputStream input, long offset) throws IOException {
        this.uploadURL = uploadURL;
        this.input = input;
        this.offset = offset;
        this.client = client;
        this.upload = upload;

        input.seekTo(offset);

        setChunkSize(5 * 1024 * 1024);
        /* Encrypt the message. */
    }

    private void openConnection() throws IOException, ProtocolException {
        // Only open a connection, if we have none open.
        if (connection != null) {
            return;
        }

        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGenerator.init(AES_KEY_SIZE);
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        keyGenerator.init(128);
        SecretKey key128 = keyGenerator.generateKey();

        key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        IV = Base64.getEncoder().encodeToString(key128.getEncoded());

//        SecureRandom random = new SecureRandom();
//        random.nextBytes(IV);

        bytesRemainingForRequest = requestPayloadSize;
        input.mark(requestPayloadSize);

        connection = (HttpURLConnection) uploadURL.openConnection();
        client.prepareConnection(connection);
        connection.setRequestProperty("Upload-Offset", Long.toString(offset));
        connection.setRequestProperty("Content-Type", "application/offset+octet-stream");
        connection.setRequestProperty("Expect", "100-continue");
        try {
            connection.setRequestMethod("PATCH");
            // Check whether we are running on a buggy JRE
        } catch (java.net.ProtocolException pe) {
            connection.setRequestMethod("POST");
            connection.setRequestProperty("X-HTTP-Method-Override", "PATCH");
        }

        connection.setDoOutput(true);
        connection.setChunkedStreamingMode(0);
        try {
            output = connection.getOutputStream();
        } catch (java.net.ProtocolException pe) {
            // If we already have a response code available, our expectation using the "Expect: 100-
            // continue" header failed and we should handle this response.
            if (connection.getResponseCode() != -1) {
                finish();
            }

            throw pe;
        }
    }

    /**
     * Sets the used chunk size. This number is used by {@link #uploadChunk(Map<String, String>)} to indicate how
     * much data is uploaded in a single take. When choosing a value for this parameter you need to
     * consider that uploadChunk() will only return once the specified number of bytes has been
     * sent. For slow internet connections this may take a long time. In addition, a buffer with
     * the chunk size is allocated and kept in memory.
     *
     * @param size The new chunk size
     */
    public void setChunkSize(int size) {
        buffer = new byte[size];
    }

    /**
     * Returns the current chunk size set using {@link #setChunkSize(int)}.
     *
     * @return Current chunk size
     */
    public int getChunkSize() {
        return buffer.length;
    }

    /**
     * Set the maximum payload size for a single request counted in bytes. This is useful for splitting
     * bigger uploads into multiple requests. For example, if you have a resource of 2MB and
     * the payload size set to 1MB, the upload will be transferred by two requests of 1MB each.
     * <p>
     * The default value for this setting is 10 * 1024 * 1024 bytes (10 MiB).
     * <p>
     * Be aware that setting a low maximum payload size (in the low megabytes or even less range) will result in decreased
     * performance since more requests need to be used for an upload. Each request will come with its overhead in terms
     * of longer upload times.
     * <p>
     * Be aware that setting a high maximum payload size may result in a high memory usage since
     * tus-java-client usually allocates a buffer with the maximum payload size (this buffer is used
     * to allow retransmission of lost data if necessary). If the client is running on a memory-
     * constrained device (e.g. mobile app) and the maximum payload size is too high, it might
     * result in an {@link OutOfMemoryError}.
     * <p>
     * This method must not be called when the uploader has currently an open connection to the
     * remote server. In general, try to set the payload size before invoking {@link #uploadChunk(Map<String, String>)}
     * the first time.
     *
     * @param size Number of bytes for a single payload
     * @throws IllegalStateException Thrown if the uploader currently has a connection open
     * @see #getRequestPayloadSize()
     */
    public void setRequestPayloadSize(int size) throws IllegalStateException {
        if (connection != null) {
            throw new IllegalStateException("payload size for a single request must not be " +
                    "modified as long as a request is in progress");
        }

        requestPayloadSize = size;
    }

    /**
     * Get the current maximum payload size for a single request.
     *
     * @return Number of bytes for a single payload
     * @see #setChunkSize(int)
     */
    public int getRequestPayloadSize() {
        return requestPayloadSize;
    }

    /**
     * Upload a part of the file by reading a chunk from the InputStream and writing
     * it to the HTTP request's body. If the number of available bytes is lower than the chunk's
     * size, all available bytes will be uploaded and nothing more.
     * No new connection will be established when calling this method, instead the connection opened
     * in the previous calls will be used.
     * The size of the read chunk can be obtained using {@link #getChunkSize()} and changed
     * using {@link #setChunkSize(int)}.
     * In order to obtain the new offset, use {@link #getOffset()} after this method returns.
     *
     * @return Number of bytes read and written.
     * @throws IOException Thrown if an exception occurs while reading from the source or writing
     *                     to the HTTP request.
     */
    public int uploadChunk(Map<String, String> data) throws IOException, ProtocolException {
        openConnection();

        int bytesToRead = Math.min(getChunkSize(), bytesRemainingForRequest);
        int bytesRead = 0;
        String base64Key = data.get("key");
        String base64IV = data.get("iv");
        try {
            bytesRead = input.read(buffer, bytesToRead);
            if (bytesRead == -1) {
                // No bytes were read since the input stream is empty
                return -1;
            }
            // Do not write the entire buffer to the stream since the array will
            // be filled up with 0x00s if the number of read bytes is lower then
            // the chunk's size.
            byte[] originalChunk = Arrays.copyOfRange(buffer, 0, bytesRead);

            byte[] encryptedBuffer = encryptData(originalChunk, base64Key, base64IV);
            output.write(encryptedBuffer, 0, encryptedBuffer.length);
            output.flush();

            offset += bytesRead;
            bytesRemainingForRequest -= bytesRead;

            if (bytesRemainingForRequest <= 0) {
                finishConnection();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return bytesRead;
    }

    /*
     * Encrypt Chuck
     */
    public static byte[] encryptData(byte[] data, String base64Key, String base64IV)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

//        byte[] encoded = key.getEncoded();
//        byte[] encoded = "DO0q.02p@NZgTb321kVxj2,.5C$,dBYz".getBytes();
//        String output = Base64.getEncoder().withoutPadding().encodeToString(encoded);
//        System.out.println("Keep it secret, keep it safe! " + output);

//        String ivoutput = Base64.getEncoder().withoutPadding().encodeToString(IV);
//        System.out.println("Keep ivoutput secret, keep it safe! " + ivoutput);

        byte[] cipherText = new byte[0];
        try {
            cipherText = encrypt(data, base64Key, base64IV);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("Encrypted Text : " + Base64.getEncoder().encodeToString(cipherText));
        return cipherText;
    }

    public static byte[] encrypt(byte[] Data, String base64Key, String base64IV) throws Exception {
        Key key = generateKey(base64Key);
        Cipher c = Cipher.getInstance(ALGO);
        IvParameterSpec iv = generateIV(base64IV);
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encVal = c.doFinal(Data);
        String encryptedValue = Base64.getEncoder().encodeToString(encVal);
       return encVal;
        // return encryptedValue.getBytes();
    }

    private static Key generateKey(String secret) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(secret.getBytes());
        Key key = new SecretKeySpec(decoded, ALGO);
        return key;
    }

    private static IvParameterSpec generateIV(String iv) throws Exception {
        byte[] decodedIV = Base64.getDecoder().decode(iv.getBytes());
        IvParameterSpec ivParameterSpec = new IvParameterSpec(decodedIV);
        return ivParameterSpec;
    }

//    public static byte[] encrypt(byte[] plaintext, SecretKey key, byte[] IV) throws Exception {
//        // Get Cipher Instance
//        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
//
//        // Create SecretKeySpec
//        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
//
//        IvParameterSpec iv = new IvParameterSpec(IV);
//
//        // Initialize Cipher for ENCRYPT_MODE
//        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
//        return cipher.update(plaintext);
//    }

    public static byte[] decrypt(byte[] plaintext, SecretKey key, byte[] IV) throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        IvParameterSpec iv = new IvParameterSpec(IV);

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        return cipher.update(plaintext);
    }

    /**
     * Upload a part of the file by read a chunks specified size from the InputStream and writing
     * it to the HTTP request's body. If the number of available bytes is lower than the chunk's
     * size, all available bytes will be uploaded and nothing more.
     * No new connection will be established when calling this method, instead the connection opened
     * in the previous calls will be used.
     * In order to obtain the new offset, use {@link #getOffset()} after this method returns.
     * <p>
     * This method ignored the payload size per request, which may be set using
     * {@link #setRequestPayloadSize(int)}. Please, use {@link #uploadChunk(Map<String, String>)} instead.
     *
     * @param chunkSize Maximum number of bytes which will be uploaded. When choosing a value
     *                  for this parameter you need to consider that the method call will only
     *                  return once the specified number of bytes have been sent. For slow
     *                  internet connections this may take a long time.
     * @return Number of bytes read and written.
     * @throws IOException Thrown if an exception occurs while reading from the source or writing
     *                     to the HTTP request.
     * @deprecated This method is inefficient and has been replaced by {@link #setChunkSize(int)}
     * and {@link #uploadChunk(Map<String, String>)} and should not be used anymore. The reason is, that
     * this method allocates a new buffer with the supplied chunk size for each time
     * it's called without reusing it. This results in a high number of memory
     * allocations and should be avoided. The new methods do not have this issue.
     */
    @Deprecated
    public int uploadChunk(int chunkSize) throws IOException, ProtocolException {
        openConnection();

        byte[] buf = new byte[chunkSize];
        int bytesRead = input.read(buf, chunkSize);
        if (bytesRead == -1) {
            // No bytes were read since the input stream is empty
            return -1;
        }
        System.out.println("uploadChuckTesting (chunksize): " + "" + bytesRead);
        // Do not write the entire buffer to the stream since the array will
        // be filled up with 0x00s if the number of read bytes is lower then
        // the chunk's size.
        output.write(buf, 0, bytesRead);
        output.flush();

        offset += bytesRead;

        return bytesRead;
    }

    /**
     * Get the current offset for the upload. This is the number of all bytes uploaded in total and
     * in all requests (not only this one). You can use it in conjunction with
     * {@link TusUpload#getSize()} to calculate the progress.
     *
     * @return The upload's current offset.
     */
    public long getOffset() {
        return offset;
    }

    public URL getUploadURL() {
        return uploadURL;
    }

    /**
     * Finish the request by closing the HTTP connection and the InputStream.
     * You can call this method even before the entire file has been uploaded. Use this behavior to
     * enable pausing uploads.
     *
     * @throws ProtocolException Thrown if the server sends an unexpected status
     *                           code
     * @throws IOException       Thrown if an exception occurs while cleaning up.
     */
    public void finish() throws ProtocolException, IOException {
        finishConnection();
        if (upload.getSize() == offset) {
            client.uploadFinished(upload);
        }

        // Close the TusInputStream after checking the response and closing the connection to ensure
        // that we will not need to read from it again in the future.
        input.close();
    }

    private void finishConnection() throws ProtocolException, IOException {
        if (output != null) output.close();

        if (connection != null) {
            int responseCode = connection.getResponseCode();
            connection.disconnect();

            if (!(responseCode >= 200 && responseCode < 300)) {
                throw new ProtocolException("unexpected status code (" + responseCode + ") while uploading chunk", connection);
            }

            // TODO detect changes and seek accordingly
            long serverOffset = getHeaderFieldLong(connection, "Upload-Offset");
            if (serverOffset == -1) {
                throw new ProtocolException("response to PATCH request contains no or invalid Upload-Offset header", connection);
            }
            if (offset != serverOffset) {
                throw new ProtocolException(
                        String.format("response contains different Upload-Offset value (%d) than expected (%d)",
                                serverOffset,
                                offset),
                        connection);
            }

            connection = null;
        }
    }

    private long getHeaderFieldLong(URLConnection connection, String field) {
        String value = connection.getHeaderField(field);
        if (value == null) {
            return -1;
        }

        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
