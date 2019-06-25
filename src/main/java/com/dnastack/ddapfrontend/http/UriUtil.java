package com.dnastack.ddapfrontend.http;

import org.springframework.http.server.reactive.ServerHttpRequest;

import java.net.URI;

import static com.dnastack.ddapfrontend.http.XForwardUtil.getExternalPath;
import static java.lang.String.format;

public class UriUtil {
    /**
     * Returns a fully-qualified URL pointing to a UI route in the given realm on this DDAP instance.
     *
     * @param request                 the inbound request from the user's browser (for calculating our return address)
     * @param realm                   the realm name to use in the returned URI
     * @param pathWithoutLeadingSlash the path component that comes after the realm. Must not begin with a slash.
     * @return absolute URI of the DDAP token endpoint for the given realm. Never null.
     */
    public static URI selfLinkToUi(ServerHttpRequest request, String realm, String pathWithoutLeadingSlash) {
        return URI.create(getExternalPath(request, format("/%s/%s", realm, pathWithoutLeadingSlash)));
    }

    /**
     * Returns a fully-qualified URL pointing to an API resource/endpoint in the given realm on this DDAP instance.
     *
     * @param request                 the inbound request from the user's browser (for calculating our return address)
     * @param realm                   the realm name to use in the returned URI
     * @param pathWithoutLeadingSlash the path component that comes after the realm. Must not begin with a slash.
     * @return absolute URI of the DDAP token endpoint for the given realm. Never null.
     */
    public static URI selfLinkToApi(ServerHttpRequest request, String realm, String pathWithoutLeadingSlash) {
        return URI.create(getExternalPath(request, format("/api/v1alpha/%s/%s", realm, pathWithoutLeadingSlash)));
    }
}
