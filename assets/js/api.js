/**
 * Enhanced API Integration with RSS Feeds and Real Data Sources
 * Supports environment variables for secure API key management
 */

class SecurityAPI {
    constructor() {
        // Use environment variable for API key (set in GitHub Actions)
        this.newsApiKey = window.NEWS_API_KEY || 'YOUR_NEWS_API_KEY';
        this.cveBaseUrl = 'https://cve.circl.lu/api';
        this.newsBaseUrl = 'https://newsapi.org/v2';
        
        // RSS Feed URLs for security news
        this.rssFeeds = [
            'https://www.securityweek.com/feed/',
            'https://feeds.feedburner.com/TheHackersNews',
            'https://www.bleepingcomputer.com/feed/',
            'https://krebsonsecurity.com/feed/',
            'https://threatpost.com/feed/'
        ];
        
        // CORS proxy for RSS feeds (since browsers block cross-origin requests)
        this.corsProxy = 'https://api.rss2json.com/v1/api.json?rss_url=';
    }

    /**
     * Fetch recent CVEs from CVE-Search API
     */
    async fetchCVEs(limit = 10) {
        try {
            const response = await fetch(`${this.cveBaseUrl}/last/${limit}`);
            if (!response.ok) throw new Error('Failed to fetch CVEs');
            
            const data = await response.json();
            return this.formatCVEData(data);
        } catch (error) {
            console.error('Error fetching CVEs:', error);
            return this.getMockCVEs(); // Fallback to mock data
        }
    }

    /**
     * Fetch security news from RSS feeds
     */
    async fetchSecurityNews(limit = 10) {
        try {
            const allNews = [];
            
            // Fetch from multiple RSS feeds
            for (const feedUrl of this.rssFeeds.slice(0, 3)) { // Limit to 3 feeds to avoid rate limits
                try {
                    const response = await fetch(`${this.corsProxy}${encodeURIComponent(feedUrl)}`);
                    if (response.ok) {
                        const data = await response.json();
                        if (data.status === 'ok' && data.items) {
                            const formattedNews = data.items.slice(0, 3).map(item => ({
                                title: this.cleanTitle(item.title),
                                summary: this.cleanSummary(item.description || item.content),
                                source: this.getSourceName(feedUrl),
                                time: this.getTimeAgo(item.pubDate),
                                url: item.link,
                                publishedAt: item.pubDate
                            }));
                            allNews.push(...formattedNews);
                        }
                    }
                } catch (feedError) {
                    console.warn(`Failed to fetch from ${feedUrl}:`, feedError);
                }
            }
            
            // If RSS feeds fail, try NewsAPI as backup
            if (allNews.length === 0) {
                const newsApiData = await this.fetchNewsAPIBackup(limit);
                allNews.push(...newsApiData);
            }
            
            // Sort by publication date and return limited results
            return allNews
                .sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt))
                .slice(0, limit);
                
        } catch (error) {
            console.error('Error fetching RSS news:', error);
            return this.getMockNews(); // Fallback to mock data
        }
    }

    /**
     * Clean HTML tags from title
     */
    cleanTitle(title) {
        return title ? title.replace(/<[^>]*>/g, '').trim() : 'No title available';
    }

    /**
     * Clean and truncate summary
     */
    cleanSummary(summary) {
        if (!summary) return 'No summary available';
        
        // Remove HTML tags and truncate
        const cleaned = summary.replace(/<[^>]*>/g, '').trim();
        return cleaned.length > 200 ? cleaned.substring(0, 200) + '...' : cleaned;
    }

    /**
     * Get source name from feed URL
     */
    getSourceName(feedUrl) {
        if (feedUrl.includes('securityweek.com')) return 'Security Week';
        if (feedUrl.includes('thehackersnews.com')) return 'The Hacker News';
        if (feedUrl.includes('bleepingcomputer.com')) return 'BleepingComputer';
        if (feedUrl.includes('krebsonsecurity.com')) return 'Krebs on Security';
        if (feedUrl.includes('threatpost.com')) return 'Threatpost';
        return 'Security News';
    }

    /**
     * Fetch security news from NewsAPI as backup
     */
    async fetchNewsAPIBackup(limit = 10) {
        if (!this.newsApiKey || this.newsApiKey === 'YOUR_NEWS_API_KEY') {
            return [];
        }
        
        try {
            const keywords = 'cybersecurity OR "data breach" OR malware OR "cyber attack" OR "vulnerability"';
            const url = `${this.newsBaseUrl}/everything?q=${encodeURIComponent(keywords)}&sortBy=publishedAt&pageSize=${limit}&apiKey=${this.newsApiKey}`;
            
            const response = await fetch(url);
            if (!response.ok) throw new Error('Failed to fetch news from NewsAPI');
            
            const data = await response.json();
            return this.formatNewsData(data.articles);
        } catch (error) {
            console.error('Error fetching NewsAPI:', error);
            return [];
        }
    }

    /**
     * Format CVE data for display
     */
    formatCVEData(cves) {
        return cves.map(cve => ({
            id: cve.id,
            description: cve.summary || 'No description available',
            severity: this.mapCVSSSeverity(cve.cvss || 0),
            score: cve.cvss || 0,
            published: new Date(cve.Published).toLocaleDateString(),
            url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`
        }));
    }

    /**
     * Format NewsAPI data for display
     */
    formatNewsData(articles) {
        return articles.filter(article => article.title && article.url).map(article => ({
            title: article.title,
            summary: article.description || article.content?.substring(0, 200) + '...',
            source: article.source.name,
            time: this.getTimeAgo(article.publishedAt),
            url: article.url,
            publishedAt: article.publishedAt
        }));
    }

    /**
     * Map CVSS score to severity level
     */
    mapCVSSSeverity(score) {
        if (score >= 9.0) return 'critical';
        if (score >= 7.0) return 'high';
        if (score >= 4.0) return 'medium';
        return 'low';
    }

    /**
     * Calculate time ago from date string
     */
    getTimeAgo(dateString) {
        const now = new Date();
        const date = new Date(dateString);
        const diffMs = now - date;
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffHours / 24);
        
        if (diffHours < 1) return 'Just now';
        if (diffHours < 24) return `${diffHours} hours ago`;
        if (diffDays === 1) return '1 day ago';
        return `${diffDays} days ago`;
    }

    /**
     * Enhanced CVE fetching with multiple sources
     */
    async fetchLatestCVEs(limit = 10) {
        try {
            // Try CVE-Search API first
            const cveSearchData = await this.fetchCVEs(limit);
            if (cveSearchData.length > 0) {
                return cveSearchData;
            }
            
            // Fallback to NIST NVD API
            const nvdResponse = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=' + limit);
            if (nvdResponse.ok) {
                const nvdData = await nvdResponse.json();
                return this.formatNVDData(nvdData.vulnerabilities || []);
            }
            
            return this.getMockCVEs();
        } catch (error) {
            console.error('Error fetching latest CVEs:', error);
            return this.getMockCVEs();
        }
    }

    /**
     * Format NIST NVD data
     */
    formatNVDData(vulnerabilities) {
        return vulnerabilities.map(vuln => {
            const cve = vuln.cve;
            const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV2?.[0]?.cvssData;
            const score = metrics?.baseScore || 0;
            
            return {
                id: cve.id,
                description: cve.descriptions?.[0]?.value || 'No description available',
                severity: this.mapCVSSSeverity(score),
                score: score,
                published: new Date(cve.published).toLocaleDateString(),
                url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
            };
        });
    }

    /**
     * Mock CVE data (fallback)
     */
    getMockCVEs() {
        return [
            {
                id: "CVE-2024-0001",
                description: "Critical buffer overflow vulnerability in OpenSSL allows remote code execution through malformed certificates.",
                severity: "critical",
                score: 9.8,
                published: new Date().toLocaleDateString(),
                url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0001"
            },
            {
                id: "CVE-2024-0002", 
                description: "SQL injection vulnerability in popular CMS allows unauthorized database access.",
                severity: "high",
                score: 8.1,
                published: new Date().toLocaleDateString(),
                url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0002"
            },
            {
                id: "CVE-2024-0003",
                description: "Cross-site scripting (XSS) vulnerability in web application framework.",
                severity: "medium",
                score: 6.5,
                published: new Date(Date.now() - 86400000).toLocaleDateString(),
                url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0003"
            }
        ];
    }

    /**
     * Mock news data with clickable URLs (fallback)
     */
    getMockNews() {
        return [
            {
                title: "Major Ransomware Group Targets Healthcare Sector",
                summary: "New sophisticated ransomware campaign specifically targeting hospital systems and medical device networks detected by security researchers.",
                source: "CyberSecNews",
                time: "2 hours ago",
                url: "https://www.bleepingcomputer.com/news/security/"
            },
            {
                title: "Zero-Day Exploit Found in Popular VPN Software",
                summary: "Critical vulnerability allows attackers to bypass authentication and gain unauthorized network access.",
                source: "Security Weekly",
                time: "4 hours ago",
                url: "https://krebsonsecurity.com/"
            },
            {
                title: "AI-Powered Phishing Attacks on the Rise",
                summary: "Cybercriminals leveraging large language models to create more convincing phishing emails and social engineering attacks.",
                source: "ThreatPost",
                time: "6 hours ago",
                url: "https://thehackernews.com/"
            },
            {
                title: "New Malware Family Targets Cryptocurrency Wallets",
                summary: "Advanced persistent threat group develops custom malware specifically designed to steal digital assets from hot wallets.",
                source: "InfoSec News",
                time: "8 hours ago",
                url: "https://www.darkreading.com/"
            }
        ];
    }
}

// Initialize API with environment variables
if (typeof window !== 'undefined') {
    window.SecurityAPI = SecurityAPI;
}

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityAPI;
}