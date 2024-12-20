package se.digg.eudiw.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.digg.eudiw.service.ParCacheService;
import se.digg.eudiw.service.ParCacheServiceInMemory;

@Configuration
public class ParCacheConfig {
    ParCacheService parCacheService() {
        return new ParCacheServiceInMemory();
    }
}
