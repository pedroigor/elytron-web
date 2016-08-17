package org.wildfly.elytron.web.undertow.server.util;

import org.infinispan.configuration.cache.CacheMode;
import org.infinispan.configuration.cache.ConfigurationBuilder;
import org.infinispan.configuration.global.GlobalConfigurationBuilder;
import org.infinispan.manager.DefaultCacheManager;
import org.infinispan.manager.EmbeddedCacheManager;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;

import java.util.concurrent.ConcurrentMap;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ClusteredIdentityCache implements IdentityCache {

    private final EmbeddedCacheManager cacheManager;
    private final ConcurrentMap<String, CachedIdentity> sessions;

    public ClusteredIdentityCache(String nodeName) {
        this.cacheManager = new DefaultCacheManager(
                GlobalConfigurationBuilder.defaultClusteredBuilder()
                        .globalJmxStatistics().cacheManagerName(nodeName)
                        .transport().nodeName(nodeName).clusterName("default-cluster")
                        .build(),
                new ConfigurationBuilder()
                        .clustering()
                        .cacheMode(CacheMode.REPL_SYNC)
                        .build()
        );
        this.sessions = cacheManager.getCache();
    }

    @Override
    public void put(CachedIdentity identity) {
        sessions.put("session-id", identity);
    }

    @Override
    public CachedIdentity get() {
        return sessions.get("session-id");
    }

    @Override
    public void remove() {
        sessions.remove("session-id");
    }
}
