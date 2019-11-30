import org.jetbrains.annotations.NotNull;
import org.w3c.dom.Node;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class StringBytesConverter {

    @NotNull
    public static String encodeString(@NotNull byte[] byteArray) {
        return Base64.getUrlEncoder().encodeToString(byteArray);
    }

    @NotNull
    public static byte[] decodeString(@NotNull String string) {
        byte[] dashed = string.getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlDecoder().decode(dashed);
    }
}