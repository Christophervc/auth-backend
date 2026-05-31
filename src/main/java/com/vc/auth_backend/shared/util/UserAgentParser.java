package com.vc.auth_backend.shared.util;

import com.vc.auth_backend.modules.auth.entity.DeviceType;
import org.springframework.stereotype.Component;

@Component
public class UserAgentParser {

    public record DeviceInfo(String deviceName, String os, DeviceType deviceType) {}

    public DeviceInfo parse(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return new DeviceInfo("Unknown", "Unknown", DeviceType.UNKNOWN);
        }

        String os = detectOs(userAgent);
        DeviceType type = detectDeviceType(userAgent, os);
        String browser = detectBrowser(userAgent);

        return new DeviceInfo(browser, os, type);
    }

    private String detectOs(String ua) {
        // iOS
        if (ua.contains("iPhone OS") || ua.contains("CPU iPhone")) {
            String version = extractVersion(ua, "iPhone OS ", "_");
            return "iOS" + (version.isEmpty() ? "" : " " + version.replace("_", "."));
        }
        if (ua.contains("iPad")) {
            String version = extractVersion(ua, "CPU OS ", "_");
            return "iPadOS" + (version.isEmpty() ? "" : " " + version.replace("_", "."));
        }
        // Android
        if (ua.contains("Android")) {
            String version = extractVersion(ua, "Android ", ";");
            return "Android" + (version.isEmpty() ? "" : " " + version);
        }
        // Windows
        if (ua.contains("Windows NT 10.0")) return "Windows 10";
        if (ua.contains("Windows NT 11.0")) return "Windows 11";
        if (ua.contains("Windows"))         return "Windows";
        // macOS
        if (ua.contains("Mac OS X")) {
            String version = extractVersion(ua, "Mac OS X ", ")");
            return "macOS" + (version.isEmpty() ? "" : " " + version.replace("_", "."));
        }
        if (ua.contains("Linux") && !ua.contains("Android")) return "Linux";
        if (ua.contains("CrOS")) return "Chrome OS";

        return "Unknown";
    }

    private DeviceType detectDeviceType(String ua, String os) {
        boolean isMobileOs = os.startsWith("Android") || os.startsWith("iOS");
        boolean isMobileUa = ua.contains("Mobile")   || ua.contains("iPhone");

        if (isMobileOs || isMobileUa) {
            boolean isTablet = ua.contains("iPad")
                    || os.startsWith("iPadOS")
                    || (os.startsWith("Android") && !ua.contains("Mobile"));
            return isTablet ? DeviceType.TABLET : DeviceType.MOBILE;
        }

        if (ua.contains("iPad") || os.startsWith("iPadOS")) {
            return DeviceType.TABLET;
        }

        if (os.startsWith("Windows")   || os.startsWith("macOS")
                || os.startsWith("Linux") || os.startsWith("Chrome OS")) {
            return DeviceType.DESKTOP;
        }
        // Fallback: UA raw en caso de que detectOs() haya devuelto "Unknown"
        if (ua.contains("Windows")   || ua.contains("Macintosh")
                || ua.contains("Linux") || ua.contains("CrOS")) {
            return DeviceType.DESKTOP;
        }
        return DeviceType.UNKNOWN;
    }

    private String detectBrowser(String ua) {
        // Orden importa: navegadores derivados de Chrome/Safari mencionan el padre en su UA
        // Edg / Edge (basado en Chromium)
        if (ua.contains("Edg/") || ua.contains("EdgA/")) {
            String version = extractVersion(ua, "Edg/", " ");
            return "Edge" + formatVersion(version);
        }
        // Firefox
        if (ua.contains("Firefox")) {
            String version = extractVersion(ua, "Firefox/", " ");
            return "Firefox" + formatVersion(version);
        }
        // Chrome (debe ir ANTES de Safari porque Chrome incluye "Safari" en su UA)
        if (ua.contains("Chrome/") && !ua.contains("Chromium")) {
            String version = extractVersion(ua, "Chrome/", " ");
            return "Chrome" + formatVersion(version);
        }
        // Chromium
        if (ua.contains("Chromium")) {
            String version = extractVersion(ua, "Chromium/", " ");
            return "Chromium" + formatVersion(version);
        }
        // Safari (debe ir DESPUÉS de Chrome porque ambos incluyen "Safari")
        if (ua.contains("Safari/") && ua.contains("Version/")) {
            String version = extractVersion(ua, "Version/", " ");
            return "Safari" + formatVersion(version);
        }
        // clientes API comunes
        if (ua.startsWith("curl"))    return "curl";
        if (ua.startsWith("PostmanRuntime")) return "Postman";
        if (ua.startsWith("insomnia")) return "Insomnia";

        return "Unknown Browser";
    }

    private String extractVersion(String ua, String token, String delimiter) {
        int start = ua.indexOf(token);
        if (start == -1) return "";
        start += token.length();
        int end = ua.indexOf(delimiter, start);
        String fullVersion = end == -1 ? ua.substring(start) : ua.substring(start, end);
        // Devolver solo el número major (antes del primer punto)
        int dotIdx = fullVersion.indexOf('.');
        return dotIdx == -1 ? fullVersion : fullVersion.substring(0, dotIdx);
    }

    private String formatVersion(String version) {
        return version.isEmpty() ? "" : " " + version;
    }
}
