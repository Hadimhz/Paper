package com.destroystokyo.paper.proxy;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMultimap;
import com.google.common.net.InetAddresses;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mojang.authlib.GameProfile;
import com.mojang.authlib.properties.Property;
import com.mojang.authlib.properties.PropertyMap;
import com.mojang.logging.LogUtils;
import io.papermc.paper.configuration.GlobalConfiguration;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.resources.Identifier;
import net.minecraft.world.entity.player.ProfilePublicKey;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;

/**
 * While Velocity supports BungeeCord-style IP forwarding, it is not secure. Users
 * have a lot of problems setting up firewalls or setting up plugins like IPWhitelist.
 * Further, the BungeeCord IP forwarding protocol still retains essentially its original
 * form, when there is brand-new support for custom login plugin messages in 1.13.
 * <p>
 * Velocity's modern IP forwarding uses an HMAC-SHA256 code to ensure authenticity
 * of messages, is packed into a binary format that is smaller than BungeeCord's
 * forwarding, and is integrated into the Minecraft login process by using the 1.13
 * login plugin message packet.
 */
public class VelocityProxy {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final String VALIDATION_API_URL = "https://vynex.hadimhz.dev/api/validate-ip";
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build();

    // Cache for IP -> Secret mappings with 5 minute sliding expiration
    // Optional.empty() means IP was looked up but has no secret (negative cache)
    private static final Cache<String, Optional<String>> SECRET_CACHE = CacheBuilder.newBuilder()
        .expireAfterAccess(5, TimeUnit.MINUTES)
        .build();

    private static final int SUPPORTED_FORWARDING_VERSION = 1;
    public static final int MODERN_FORWARDING_WITH_KEY = 2;
    public static final int MODERN_FORWARDING_WITH_KEY_V2 = 3;
    public static final int MODERN_LAZY_SESSION = 4;
    public static final byte MAX_SUPPORTED_FORWARDING_VERSION = MODERN_LAZY_SESSION;
    public static final Identifier PLAYER_INFO_CHANNEL = Identifier.fromNamespaceAndPath("velocity", "player_info");

    public static boolean checkIntegrity(final FriendlyByteBuf buf) {
        return checkIntegrity(buf, GlobalConfiguration.get().proxies.velocity.secret);
    }

    public static boolean checkIntegrity(final FriendlyByteBuf buf, String secret) {

        if (secret.isEmpty())
            return false;

        final byte[] signature = new byte[32];
        buf.readBytes(signature);

        final byte[] data = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), data);

        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
            final byte[] mySignature = mac.doFinal(data);
            if (!MessageDigest.isEqual(signature, mySignature)) {
                return false;
            }
        } catch (final InvalidKeyException | NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }

        return true;
    }

    public static InetAddress readAddress(final FriendlyByteBuf buf) {
        return InetAddresses.forString(buf.readUtf(Short.MAX_VALUE));
    }

    public static GameProfile createProfile(final FriendlyByteBuf buf) {
        return new GameProfile(buf.readUUID(), buf.readUtf(16), readProperties(buf));
    }

    private static PropertyMap readProperties(final FriendlyByteBuf buf) {
        final ImmutableMultimap.Builder<String, Property> propertiesBuilder = ImmutableMultimap.builder();
        final int properties = buf.readVarInt();
        for (int i1 = 0; i1 < properties; i1++) {
            final String name = buf.readUtf(Short.MAX_VALUE);
            final String value = buf.readUtf(Short.MAX_VALUE);
            final String signature = buf.readBoolean() ? buf.readUtf(Short.MAX_VALUE) : null;
            propertiesBuilder.put(name, new Property(name, value, signature));
        }
        final ImmutableMultimap<String, Property> propertiesMap = propertiesBuilder.build();
        return new PropertyMap(propertiesMap);
    }

    public static ProfilePublicKey.Data readForwardedKey(FriendlyByteBuf buf) {
        return new ProfilePublicKey.Data(buf);
    }

    public static UUID readSignerUuidOrElse(FriendlyByteBuf buf, UUID orElse) {
        return buf.readBoolean() ? buf.readUUID() : orElse;
    }

    /**
     * Fetches the secret key for a given IP address from the validation API.
     * Results are cached for 5 minutes (sliding expiration).
     *
     * @param adminKey The admin API key for authentication
     * @param ip The IP address to look up
     * @return The secret key if found, or null if not found or on error
     */
    public static @Nullable String fetchSecretForIp(String adminKey, String ip) {
        if (adminKey == null || adminKey.isEmpty()) {
            return null;
        }

        // Check cache first (this also refreshes the expiration timer)
        Optional<String> cached = SECRET_CACHE.getIfPresent(ip);
        if (cached != null) {
            return cached.orElse(null);
        }

        // Not in cache, fetch from API
        try {
            String requestBody = "{\"ip\": \"" + ip + "\"}";

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(VALIDATION_API_URL))
                .header("X-Admin-API-Key", adminKey)
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
                if (json.has("exists") && json.get("exists").getAsBoolean() && json.has("secret")) {
                    String secret = json.get("secret").getAsString();
                    SECRET_CACHE.put(ip, Optional.of(secret));
                    return secret;
                }
            } else {
                LOGGER.warn("Velocity IP validation API returned status {} for IP {}", response.statusCode(), ip);
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to fetch secret from validation API for IP {}: {}", ip, e.getMessage());
        }

        // Cache negative result too (no secret found)
        SECRET_CACHE.put(ip, Optional.empty());
        return null;
    }

    /**
     * Clears the secret cache. Useful for testing or if secrets have been updated.
     */
    public static void clearSecretCache() {
        SECRET_CACHE.invalidateAll();
    }
}
