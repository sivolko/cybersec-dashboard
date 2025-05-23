/**
 * Real API Integration Functions
 * Replace mock data with real API calls
 */

class SecurityAPI {
    constructor() {
        this.cveBaseUrl = 'https://cve.circl.lu/api';
        this.newsApiKey = 'YOUR_NEWS_API_KEY'; // Get from newsapi.org
        this.newsBaseUrl = 'https://newsapi.org/v2';
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
     * Fetch security news from NewsAPI
     */
    async fetchSecurityNews(limit = 10) {
        try {
            const keywords = 'cybersecurity OR "data breach" OR malware OR "cyber attack"';
            const url = `${this.newsBaseUrl}/everything?q=${encodeURIComponent(keywords)}&sortBy=publishedAt&pageSize=${limit}&apiKey=${this.newsApiKey}`;
            
            const response = await fetch(url);
            if (!response.ok) throw new Error('Failed to fetch news');
            
            const data = await response.json();
            return this.formatNewsData(data.articles);
        } catch (error) {
            console.error('Error fetching news:', error);
            return this.getMockNews(); // Fallback to mock data
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
            published: new Date(cve.Published).toLocaleDateString()
        }));
    }

    /**
     * Format news data for display
     */
    formatNewsData(articles) {
        return articles.map(article => ({
            title: article.title,
            summary: article.description || article.content?.substring(0, 200) + '...',
            source: article.source.name,
            time: this.getTimeAgo(article.publishedAt),
            url: article.url
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
        
        if (diffHours < 1) return 'Just now';
        if (diffHours < 24) return `${diffHours} hours ago`;
        return `${Math.floor(diffHours / 24)} days ago`;
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
                published: new Date().toLocaleDateString()
            },
            {
                id: "CVE-2024-0002", 
                description: "SQL injection vulnerability in popular CMS allows unauthorized database access.",
                severity: "high",
                score: 8.1,
                published: new Date().toLocaleDateString()
            },
            {
                id: "CVE-2024-0003",
                description: "Cross-site scripting (XSS) vulnerability in web application framework.",
                severity: "medium",
                score: 6.5,
                published: new Date(Date.now() - 86400000).toLocaleDateString()
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
                time: "2 hours ago"
            },
            {
                title: "Zero-Day Exploit Found in Popular VPN Software",
                summary: "Critical vulnerability allows attackers to bypass authentication and gain unauthorized network access.",
                source: "Security Weekly",
                time: "4 hours ago"
            },
            {
                title: "AI-Powered Phishing Attacks on the Rise",
                summary: "Cybercriminals leveraging large language models to create more convincing phishing emails and social engineering attacks.",
                source: "ThreatPost",
                time: "6 hours ago"
            }
        ];
    }
}

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityAPI;
}