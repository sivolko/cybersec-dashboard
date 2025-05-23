# API Integration Guide

This guide explains how to integrate real APIs into the CyberSec Dashboard.

## CVE Data Sources

### 1. NIST NVD API
- **URL**: `https://services.nvd.nist.gov/rest/json/cves/2.0/`
- **Documentation**: https://nvd.nist.gov/developers/vulnerabilities
- **Rate Limit**: 50 requests per 30 seconds (without API key)
- **Free**: Yes (with rate limits)

### 2. CVE-Search API
- **URL**: `https://cve.circl.lu/api/`
- **Documentation**: https://cve.circl.lu/api/
- **Rate Limit**: Reasonable usage
- **Free**: Yes

## Security News Sources

### 1. NewsAPI
- **URL**: `https://newsapi.org/v2/`
- **Documentation**: https://newsapi.org/docs
- **Rate Limit**: 1000 requests/day (free)
- **Setup**: Requires API key

### 2. RSS Feeds
Popular security blogs and news sources:
- `https://feeds.feedburner.com/TheHackersNews`
- `https://krebsonsecurity.com/feed/`
- `https://www.bleepingcomputer.com/feed/`
- `https://threatpost.com/feed/`

## Implementation Steps

### Step 1: Get API Keys
1. Sign up for NewsAPI: https://newsapi.org/register
2. Get your API key from the dashboard
3. Replace `YOUR_NEWS_API_KEY` in `assets/js/api.js`

### Step 2: Update API Configuration
```javascript
// In assets/js/api.js
constructor() {
    this.newsApiKey = 'your-actual-api-key-here';
    // ... other configuration
}
```

### Step 3: Enable CORS (if needed)
For local development, you might need to handle CORS:

```javascript
// Use a CORS proxy for development
const proxyUrl = 'https://cors-anywhere.herokuapp.com/';
const targetUrl = 'https://cve.circl.lu/api/last/10';
fetch(proxyUrl + targetUrl)
```

### Step 4: Error Handling
Implement proper error handling:

```javascript
async fetchData() {
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        return this.getFallbackData();
    }
}
```

## Security Considerations

### 1. API Key Protection
- Never commit API keys to public repositories
- Use environment variables or config files
- Consider server-side proxy for sensitive APIs

### 2. Input Validation
- Validate all API responses
- Sanitize data before displaying
- Handle malformed JSON gracefully

### 3. Rate Limiting
- Respect API rate limits
- Implement exponential backoff
- Cache responses when appropriate

## Testing APIs

### Local Testing
```bash
# Test CVE API
curl "https://cve.circl.lu/api/last/5"

# Test News API (replace YOUR_API_KEY)
curl "https://newsapi.org/v2/everything?q=cybersecurity&apiKey=YOUR_API_KEY"
```

### Browser Testing
```javascript
// Test in browser console
fetch('https://cve.circl.lu/api/last/5')
    .then(response => response.json())
    .then(data => console.log(data));
```

## Deployment Considerations

### Environment Variables
For production deployment, use environment variables:

```javascript
const config = {
    newsApiKey: process.env.NEWS_API_KEY || 'fallback-key',
    cveApiUrl: process.env.CVE_API_URL || 'https://cve.circl.lu/api'
};
```

### Caching Strategy
Implement caching to reduce API calls:

```javascript
class ApiCache {
    constructor(ttl = 300000) { // 5 minutes
        this.cache = new Map();
        this.ttl = ttl;
    }
    
    get(key) {
        const item = this.cache.get(key);
        if (item && Date.now() - item.timestamp < this.ttl) {
            return item.data;
        }
        this.cache.delete(key);
        return null;
    }
    
    set(key, data) {
        this.cache.set(key, {
            data,
            timestamp: Date.now()
        });
    }
}
```

## Performance Optimization

### 1. Request Batching
Combine multiple API requests into fewer calls when possible.

### 2. Progressive Loading
Load critical data first, then enhance with additional information.

### 3. Background Updates
Use Web Workers for heavy API processing to keep the UI responsive.

## Troubleshooting

### Common Issues

**1. CORS Errors:**
- Use a CORS proxy for development
- Set up proper CORS headers on your server
- Consider using server-side API calls

**2. Rate Limiting:**
- Implement exponential backoff
- Cache responses appropriately
- Use multiple API keys for higher limits

**3. API Unavailability:**
- Always have fallback data
- Show meaningful error messages
- Implement retry mechanisms

### Getting Help
- Check API documentation for updates
- Monitor API status pages
- Join relevant developer communities