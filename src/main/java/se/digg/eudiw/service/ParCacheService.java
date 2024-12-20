package se.digg.eudiw.service;

import org.springframework.util.MultiValueMap;

import java.util.Map;

public interface ParCacheService {
    void saveParParams(String requestId, MultiValueMap<String, String> storedParams, int ttl);
    MultiValueMap<String, String> loadParParamsAndRemoveFromCache(String requestId);
}