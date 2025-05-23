/**
 * Enhanced API Integration with RSS Feeds and Dynamic Configuration
 * Uses GitHub secrets for API keys and RSS feeds for real-time data
 */

class SecurityAPI {
    constructor() {
        // Use environment variables for API keys (GitHub secrets)
        this.newsApiKey = window.NEWS_API_KEY || 'demo-key';
        this.cveBaseUrl = 'https://cve.circl.lu/api';
        this.newsBaseUrl = 'https://newsapi.org/v2';
        
        // RSS Feed URLs for real-time security news
        this.rssFeedUrls = [
            'https://feeds.feedburner.com/securityweek',
            'https://www.bleepingcomputer.com/feed/',
            'https://feeds.feedburner.com/TheHackersNews',
            'https://krebsonsecurity.com/feed/',
            'https://threatpost.com/feed/'
        ];
        
        // CORS proxy for RSS feeds (free service)
        this.corsProxy = 'https://api.allorigins.win/get?url=';
    }

    /**
     * Fetch recent CVEs from multiple sources
     */
    async fetchCVEs(limit = 10) {
        try {
            // Try CVE-Search API first
            const response = await fetch(`${this.cveBaseUrl}/last/${limit}`);
            if (response.ok) {
                const data = await response.json();
                return this.formatCVEData(data);
            }
        } catch (error) {
            console.error('Error fetching CVEs from primary source:', error);
        }

        // Fallback to NVD API
        try {
            const nvdResponse = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=10');
            if (nvdResponse.ok) {
                const nvdData = await nvdResponse.json();
                return this.formatNVDData(nvdData.vulnerabilities);
            }
        } catch (error) {
            console.error('Error fetching CVEs from NVD:', error);
        }

        // Final fallback to mock data
        return this.getMockCVEs();
    }

    /**
     * Fetch security news from RSS feeds
     */
    async fetchSecurityNews(limit = 8) {
        try {
            const newsArticles = [];
            
            // Fetch from multiple RSS feeds
            for (const feedUrl of this.rssFeedUrls.slice(0, 3)) { // Use first 3 feeds
                try {
                    const articles = await this.fetchFromRSSFeed(feedUrl, 3);
                    newsArticles.push(...articles);
                } catch (error) {
                    console.error(`Error fetching from ${feedUrl}:`, error);
                }
            }

            // Sort by date and limit results
            const sortedArticles = newsArticles
                .sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt))
                .slice(0, limit);

            return sortedArticles.length > 0 ? sortedArticles : this.getMockNews();
        } catch (error) {
            console.error('Error fetching RSS news:', error);
            return this.getMockNews();
        }
    }

    /**
     * Fetch articles from RSS feed using CORS proxy
     */
    async fetchFromRSSFeed(feedUrl, limit = 3) {
        try {
            const proxyUrl = `${this.corsProxy}${encodeURIComponent(feedUrl)}`;
            const response = await fetch(proxyUrl);
            const data = await response.json();
            
            // Parse XML content
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(data.contents, 'text/xml');
            const items = xmlDoc.querySelectorAll('item');
            
            const articles = [];
            for (let i = 0; i < Math.min(items.length, limit); i++) {
                const item = items[i];
                const title = item.querySelector('title')?.textContent || 'No title';
                const description = item.querySelector('description')?.textContent || 'No description';
                const link = item.querySelector('link')?.textContent || '#';
                const pubDate = item.querySelector('pubDate')?.textContent || new Date().toISOString();
                
                articles.push({
                    title: this.cleanHtml(title),
                    summary: this.cleanHtml(description).substring(0, 200) + '...',
                    source: this.getSourceFromUrl(feedUrl),
                    time: this.getTimeAgo(pubDate),
                    url: link,
                    publishedAt: pubDate
                });
            }
            
            return articles;
        } catch (error) {
            console.error(`Error parsing RSS feed ${feedUrl}:`, error);
            return [];
        }
    }

    /**
     * Format CVE data from CVE-Search API
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
     * Format CVE data from NVD API
     */
    formatNVDData(vulnerabilities) {
        return vulnerabilities.map(vuln => {
            const cve = vuln.cve;
            const cvssData = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV30?.[0] || {};
            const score = cvssData.cvssData?.baseScore || 0;
            
            return {
                id: cve.id,
                description: cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description available',
                severity: this.mapCVSSSeverity(score),
                score: score,
                published: new Date(cve.published).toLocaleDateString(),
                url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
            };
        });
    }

    /**
     * Get source name from RSS feed URL
     */
    getSourceFromUrl(url) {
        if (url.includes('securityweek')) return 'SecurityWeek';
        if (url.includes('bleepingcomputer')) return 'BleepingComputer';
        if (url.includes('thehackersnews')) return 'The Hacker News';
        if (url.includes('krebsonsecurity')) return 'Krebs on Security';
        if (url.includes('threatpost')) return 'Threatpost';
        return 'Security News';
    }

    /**
     * Clean HTML tags from text
     */
    cleanHtml(text) {
        const div = document.createElement('div');
        div.innerHTML = text;
        return div.textContent || div.innerText || '';
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
        
        if (diffHours < 1) return 'Just now';
        if (diffHours < 24) return `${diffHours} hours ago`;
        const diffDays = Math.floor(diffHours / 24);
        if (diffDays === 1) return '1 day ago';
        if (diffDays < 7) return `${diffDays} days ago`;
        return new Date(dateString).toLocaleDateString();
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
     * Mock news data (fallback)
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
            }
        ];
    }
}

// Initialize API with environment variables support
const securityAPI = new SecurityAPI();

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityAPI;
}