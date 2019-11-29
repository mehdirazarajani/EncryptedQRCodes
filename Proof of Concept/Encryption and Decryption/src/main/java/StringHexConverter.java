import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

public class StringHexConverter {

    @NotNull
    @Contract("_ -> new")
    private static String asHex(@NotNull byte[] buf) {
        final char[] HEX_CHARS;
        HEX_CHARS = "0123456789abcdef".toCharArray();

        char[] chars = new char[2 * buf.length];
        for (int i = 0; i < buf.length; ++i) {
            chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
        }
        return new String(chars);
    }

    @NotNull
    @Contract("null -> fail")
    public static String stringToHex(String input) {
        if (input == null) throw new NullPointerException();
        return asHex(input.getBytes());
    }

    @NotNull
    @Contract("_ -> new")
    public static String hexToString(@NotNull String txtInHex) {
        byte[] txtInByte = new byte[txtInHex.length() / 2];
        int j = 0;
        for (int i = 0; i < txtInHex.length(); i += 2) {
            txtInByte[j++] = Byte.parseByte(txtInHex.substring(i, i + 2), 16);
        }
        return new String(txtInByte);
    }
}

