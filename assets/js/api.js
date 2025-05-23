/**
 * Real API Integration Functions
 * Uses environment variables for secure API key management
 */

class SecurityAPI {
    constructor() {
        this.cveBaseUrl = 'https://cve.circl.lu/api';
        // API key will be injected during build process
        this.newsApiKey = window.NEWS_API_KEY || 'demo-key';
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
            // Use real API if key is available
            if (this.newsApiKey && this.newsApiKey !== 'demo-key') {
                const keywords = 'cybersecurity OR "data breach" OR malware OR "cyber attack"';
                const url = `${this.newsBaseUrl}/everything?q=${encodeURIComponent(keywords)}&sortBy=publishedAt&pageSize=${limit}&apiKey=${this.newsApiKey}`;
                
                const response = await fetch(url);
                if (response.ok) {
                    const data = await response.json();
                    return this.formatNewsData(data.articles);
                }
            }
            
            // Fallback to mock data if API fails or no key
            console.log('Using mock news data - API key not configured or API unavailable');
            return this.getMockNews();
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
        return articles.slice(0, 10).map(article => ({
            title: article.title,
            summary: article.description || article.content?.substring(0, 200) + '...' || 'No summary available',
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
     * Enhanced mock CVE data (fallback)
     */
    getMockCVEs() {
        const today = new Date().toLocaleDateString();
        const yesterday = new Date(Date.now() - 86400000).toLocaleDateString();
        
        return [
            {
                id: "CVE-2024-5001",
                description: "Critical remote code execution vulnerability in Apache HTTP Server allows attackers to execute arbitrary code via malformed request headers.",
                severity: "critical",
                score: 9.8,
                published: today
            },
            {
                id: "CVE-2024-5002", 
                description: "SQL injection vulnerability in WordPress plugin allows unauthorized database access and potential data exfiltration.",
                severity: "high",
                score: 8.1,
                published: today
            },
            {
                id: "CVE-2024-5003",
                description: "Cross-site scripting (XSS) vulnerability in popular JavaScript framework enables client-side code injection.",
                severity: "medium",
                score: 6.5,
                published: yesterday
            },
            {
                id: "CVE-2024-5004",
                description: "Information disclosure vulnerability in cloud storage API exposes sensitive configuration data.",
                severity: "low",
                score: 3.2,
                published: yesterday
            },
            {
                id: "CVE-2024-5005",
                description: "Buffer overflow in network driver allows local privilege escalation on Linux systems.",
                severity: "high",
                score: 7.8,
                published: today
            }
        ];
    }

    /**
     * Enhanced mock news data (fallback)
     */
    getMockNews() {
        return [
            {
                title: "Major Healthcare Ransomware Attack Affects 100+ Hospitals",
                summary: "Sophisticated ransomware campaign targets hospital systems across multiple countries, disrupting patient care and exposing sensitive medical data.",
                source: "CyberSecurity Today",
                time: "1 hour ago"
            },
            {
                title: "Zero-Day Vulnerability Discovered in Popular VPN Client",
                summary: "Security researchers identify critical authentication bypass vulnerability affecting millions of remote workers worldwide.",
                source: "InfoSec Weekly",
                time: "3 hours ago"
            },
            {
                title: "AI-Generated Phishing Emails Bypass Traditional Security",
                summary: "Cybercriminals leverage advanced language models to create highly convincing phishing campaigns with 40% higher success rates.",
                source: "ThreatIntel Report",
                time: "5 hours ago"
            },
            {
                title: "New Cryptocurrency Mining Malware Targets Cloud Infrastructure",
                summary: "Advanced persistent threat group develops sophisticated malware specifically designed to compromise cloud computing resources.",
                source: "Cloud Security News",
                time: "7 hours ago"
            },
            {
                title: "Supply Chain Attack Compromises 500+ Software Packages",
                summary: "Coordinated attack on popular package repositories affects thousands of applications in what experts call the largest supply chain compromise of 2024.",
                source: "DevSec Alert",
                time: "9 hours ago"
            },
            {
                title: "Nation-State Actors Target Critical Infrastructure",
                summary: "Intelligence agencies warn of increased cyber attacks against power grids and water treatment facilities across multiple regions.",
                source: "National Cyber Security",
                time: "12 hours ago"
            }
        ];
    }
}

// Initialize API when script loads
let securityAPI;
document.addEventListener('DOMContentLoaded', () => {
    securityAPI = new SecurityAPI();
});

// Export for use in main application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityAPI;
}