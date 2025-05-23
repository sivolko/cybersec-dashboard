/**
 * Enhanced API Integration with RSS Feeds
 * Real-time CVE and Security News from RSS sources
 */

class SecurityAPI {
    constructor() {
        // Use environment variable for API key (set in GitHub secrets)
        this.newsApiKey = process.env.NEWS_API_KEY || window.NEWS_API_KEY || 'demo-key';
        this.newsBaseUrl = 'https://newsapi.org/v2';
        
        // RSS Feed URLs for real-time security news
        this.rssFeedUrls = [
            'https://www.securityweek.com/feed/',
            'https://feeds.feedburner.com/eset/blog',
            'https://www.bleepingcomputer.com/feed/',
            'https://krebsonsecurity.com/feed/',
            'https://threatpost.com/feed/',
            'https://www.darkreading.com/rss.xml'
        ];
        
        // CVE Feed URLs
        this.cveFeedUrls = [
            'https://cve.mitre.org/data/downloads/allitems-cvrf.xml',
            'https://nvd.nist.gov/feeds/json/cve/1.1/recent.json'
        ];
        
        // CORS proxy for RSS feeds (since we're running in browser)
        this.corsProxy = 'https://api.allorigins.win/raw?url=';
    }

    /**
     * Fetch latest CVEs from multiple sources
     */
    async fetchCVEs(limit = 10) {
        try {
            console.log('🔍 Fetching latest CVEs...');
            
            // Try NIST NVD API first
            const nvdData = await this.fetchFromNVD(limit);
            if (nvdData && nvdData.length > 0) {
                return nvdData;
            }
            
            // Fallback to CVE-Search API
            const cveSearchData = await this.fetchFromCVESearch(limit);
            if (cveSearchData && cveSearchData.length > 0) {
                return cveSearchData;
            }
            
            // Final fallback to mock data
            console.warn('⚠️ Using mock CVE data - APIs unavailable');
            return this.getMockCVEs();
            
        } catch (error) {
            console.error('❌ Error fetching CVEs:', error);
            return this.getMockCVEs();
        }
    }

    /**
     * Fetch CVEs from NIST NVD
     */
    async fetchFromNVD(limit) {
        try {
            const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=${limit}&startIndex=0`);
            if (!response.ok) throw new Error('NVD API failed');
            
            const data = await response.json();
            return data.vulnerabilities?.map(vuln => ({
                id: vuln.cve.id,
                description: vuln.cve.descriptions?.[0]?.value || 'No description available',
                severity: this.mapCVSSSeverity(vuln.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0),
                score: vuln.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0,
                published: new Date(vuln.cve.published).toLocaleDateString(),
                url: `https://nvd.nist.gov/vuln/detail/${vuln.cve.id}`
            })) || [];
        } catch (error) {
            console.error('NVD API error:', error);
            return null;
        }
    }

    /**
     * Fetch CVEs from CVE-Search API
     */
    async fetchFromCVESearch(limit) {
        try {
            const response = await fetch(`https://cve.circl.lu/api/last/${limit}`);
            if (!response.ok) throw new Error('CVE-Search API failed');
            
            const data = await response.json();
            return this.formatCVEData(data);
        } catch (error) {
            console.error('CVE-Search API error:', error);
            return null;
        }
    }

    /**
     * Fetch security news from RSS feeds
     */
    async fetchSecurityNews(limit = 10) {
        try {
            console.log('📰 Fetching latest security news from RSS feeds...');
            
            const allNews = [];
            
            // Fetch from multiple RSS sources in parallel
            const feedPromises = this.rssFeedUrls.slice(0, 3).map(async (feedUrl) => {
                try {
                    const news = await this.parseRSSFeed(feedUrl, 3);
                    return news;
                } catch (error) {
                    console.warn(`⚠️ Failed to fetch from ${feedUrl}:`, error);
                    return [];
                }
            });
            
            const feedResults = await Promise.allSettled(feedPromises);
            
            // Combine all successful results
            feedResults.forEach(result => {
                if (result.status === 'fulfilled' && result.value) {
                    allNews.push(...result.value);
                }
            });
            
            // Sort by publication date (newest first)
            allNews.sort((a, b) => new Date(b.pubDate) - new Date(a.pubDate));
            
            // Return limited results or fallback to mock data
            if (allNews.length > 0) {
                return allNews.slice(0, limit);
            } else {
                console.warn('⚠️ Using mock news data - RSS feeds unavailable');
                return this.getMockNews();
            }
            
        } catch (error) {
            console.error('❌ Error fetching security news:', error);
            return this.getMockNews();
        }
    }

    /**
     * Parse RSS feed and extract articles
     */
    async parseRSSFeed(feedUrl, limit = 5) {
        try {
            // Use CORS proxy to fetch RSS feed
            const proxyUrl = `${this.corsProxy}${encodeURIComponent(feedUrl)}`;
            const response = await fetch(proxyUrl);
            
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const xmlText = await response.text();
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(xmlText, 'text/xml');
            
            // Check for parsing errors
            const parserError = xmlDoc.querySelector('parsererror');
            if (parserError) throw new Error('XML parsing failed');
            
            // Extract items from RSS feed
            const items = xmlDoc.querySelectorAll('item');
            const articles = [];
            
            for (let i = 0; i < Math.min(items.length, limit); i++) {
                const item = items[i];
                
                const title = item.querySelector('title')?.textContent?.trim();
                const description = item.querySelector('description')?.textContent?.trim();
                const link = item.querySelector('link')?.textContent?.trim();
                const pubDate = item.querySelector('pubDate')?.textContent?.trim();
                
                if (title && description && link) {
                    articles.push({
                        title,
                        summary: this.cleanDescription(description),
                        url: link,
                        source: this.extractSourceName(feedUrl),
                        time: this.getTimeAgo(pubDate),
                        pubDate: pubDate || new Date().toISOString()
                    });
                }
            }
            
            return articles;
        } catch (error) {
            console.error(`RSS parsing error for ${feedUrl}:`, error);
            return [];
        }
    }

    /**
     * Clean and truncate article description
     */
    cleanDescription(description) {
        if (!description) return 'No description available';
        
        // Remove HTML tags and decode entities
        const cleaned = description
            .replace(/<[^>]*>/g, '') // Remove HTML tags
            .replace(/&[^;]+;/g, ' ') // Remove HTML entities
            .replace(/\s+/g, ' ') // Normalize whitespace
            .trim();
        
        // Truncate to reasonable length
        return cleaned.length > 200 ? cleaned.substring(0, 200) + '...' : cleaned;
    }

    /**
     * Extract source name from feed URL
     */
    extractSourceName(feedUrl) {
        const sourceMap = {
            'securityweek.com': 'SecurityWeek',
            'bleepingcomputer.com': 'BleepingComputer',
            'krebsonsecurity.com': 'Krebs on Security',
            'threatpost.com': 'Threatpost',
            'darkreading.com': 'Dark Reading',
            'eset.com': 'ESET Blog'
        };
        
        for (const [domain, name] of Object.entries(sourceMap)) {
            if (feedUrl.includes(domain)) return name;
        }
        
        return 'Security News';
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
        if (!dateString) return 'Unknown';
        
        const now = new Date();
        const date = new Date(dateString);
        
        if (isNaN(date.getTime())) return 'Unknown';
        
        const diffMs = now - date;
        const diffMinutes = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        
        if (diffMinutes < 60) return `${diffMinutes} minutes ago`;
        if (diffHours < 24) return `${diffHours} hours ago`;
        if (diffDays < 7) return `${diffDays} days ago`;
        return date.toLocaleDateString();
    }

    /**
     * Enhanced mock CVE data (fallback)
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
     * Enhanced mock news data (fallback)
     */
    getMockNews() {
        return [
            {
                title: "Major Ransomware Group Targets Healthcare Sector",
                summary: "New sophisticated ransomware campaign specifically targeting hospital systems and medical device networks detected by security researchers.",
                source: "SecurityWeek",
                time: "2 hours ago",
                url: "https://www.securityweek.com/ransomware-healthcare"
            },
            {
                title: "Zero-Day Exploit Found in Popular VPN Software",
                summary: "Critical vulnerability allows attackers to bypass authentication and gain unauthorized network access.",
                source: "BleepingComputer",
                time: "4 hours ago",
                url: "https://www.bleepingcomputer.com/vpn-zero-day"
            },
            {
                title: "AI-Powered Phishing Attacks on the Rise",
                summary: "Cybercriminals leveraging large language models to create more convincing phishing emails and social engineering attacks.",
                source: "Threatpost",
                time: "6 hours ago",
                url: "https://threatpost.com/ai-phishing-attacks"
            }
        ];
    }
}

// Make SecurityAPI available globally
window.SecurityAPI = SecurityAPI;