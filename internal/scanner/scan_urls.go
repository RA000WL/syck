package scanner

import (
	"github.com/RA000WL/syck/internal/adaptive"
	"github.com/RA000WL/syck/internal/correlator"
	"github.com/RA000WL/syck/internal/crawler"
	"github.com/RA000WL/syck/internal/finding"
)

func ScanURLs(urls []string, cfg Config) ([]finding.Finding, error) {
	// Build HTTP client with custom headers
	httpClient := buildHTTPClient(cfg)

	// Build crawl config
	crawlCfg := buildCrawlConfig(cfg, httpClient)

	// Open URL cache if configured
	if cfg.URLCacheDB != "" {
		if urlCache, uErr := crawler.OpenURLCache(cfg.URLCacheDB); uErr == nil {
			defer urlCache.Close()
			crawlCfg.URLCache = urlCache
		}
	}

	// Crawl URLs
	crawled := crawler.Crawl(urls, crawlCfg)

	var (
		allFindings   []finding.Finding
		urlsScanned   int64
		totalFindings int64
	)

	// Probe juicy files
	allFindings = append(allFindings, probeJuicyFiles(httpClient, crawled, cfg)...)

	// Scan crawled content
	allFindings = append(allFindings, scanCrawledContent(crawled, cfg, &urlsScanned, &totalFindings)...)

	// Extract endpoints
	allFindings = append(allFindings, extractEndpointsFromCrawl(crawled, cfg)...)

	// Detect cloud storage
	allFindings = append(allFindings, detectCloudStorage(crawled)...)

	// Probe GraphQL
	allFindings = append(allFindings, probeGraphQLEndpoints(httpClient, crawled, cfg)...)

	// Parse OpenAPI specs
	allFindings = append(allFindings, parseOpenAPISpecs(crawled, cfg)...)

	// Analyze security headers
	if cfg.HeaderCheck {
		allFindings = append(allFindings, analyzeSecurityHeaders(httpClient, crawled)...)
	}

	// Detect technologies
	if cfg.TechDetect {
		allFindings = append(allFindings, detectTechnologies(httpClient, crawled)...)
		allFindings = append(allFindings, detectWAF(httpClient, crawled)...)
	}

	// Analyze source maps for exposed files
	allFindings = append(allFindings, analyzeSourceMaps(httpClient, crawled, cfg)...)

	// Post-processing
	if !cfg.NoDedup {
		allFindings = finding.Deduplicate(allFindings)
		allFindings = finding.DeduplicateBySecret(allFindings)
	}
	if cfg.DowngradeFP {
		allFindings = DowngradeFP(allFindings)
	}

	allFindings = correlateFindings(cfg, allFindings)

	// Cache and adaptive learning
	if cfg.CacheDB != "" {
		if cache, err := correlator.OpenCache(cfg.CacheDB); err == nil {
			recordFingerprints(cache, allFindings)
			if cfg.Adaptive && cfg.AdaptiveWeights != nil {
				for i := range allFindings {
					filePattern := adaptive.ExtractFilePattern(allFindings[i].File)
					w := cfg.AdaptiveWeights.Get(allFindings[i].RuleName, filePattern)
					if w != nil {
						allFindings[i].AdaptiveModifier = int(w.Modifier)
						allFindings[i].LearningTier = w.Tier.Label()
					}
				}
			}
			cache.Close()
		}
	}

	return allFindings, nil
}
