# 🛡️ CyberSec Dashboard - Real-time Security Intelligence

A modern, responsive dashboard for monitoring CVEs, security news, and security best practices in real-time.

## 🌟 Features

- **Real-time CVE Monitoring** - Latest vulnerability information with severity ratings
- **Security News Feed** - Curated security news from multiple sources
- **Security Tips & Best Practices** - Expert recommendations and guidelines
- **Interactive UI** - Modern card-based design with smooth animations
- **Responsive Design** - Works perfectly on desktop and mobile devices
- **Live Statistics** - Real-time metrics and threat level indicators
- **Auto-refresh** - Automatic data updates every 5 minutes

## 🚀 Live Demo

[View Live Dashboard](https://sivolko.github.io/cybersec-dashboard/)

## 🛠️ Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Styling**: Custom CSS with modern gradients and animations
- **Icons**: Font Awesome 6.4.0
- **Hosting**: GitHub Pages
- **API Integration**: Ready for real CVE feeds and news APIs

## 📋 Setup Instructions

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/sivolko/cybersec-dashboard.git
   cd cybersec-dashboard
   ```

2. **Open locally**
   ```bash
   # Simple HTTP server
   python -m http.server 8000
   
   # Or use Node.js
   npx serve .
   
   # Or just open index.html in your browser
   ```

3. **Visit** `http://localhost:8000`

### GitHub Pages Deployment

1. Push to GitHub repository
2. Go to Settings → Pages
3. Select "Deploy from a branch" 
4. Choose `main` branch and `/ (root)` folder
5. Your dashboard will be live at `https://sivolko.github.io/cybersec-dashboard/`

## 🔧 Customization

### Adding Real API Integration

Replace the mock data with real API calls by updating the JavaScript section.

### Supported APIs

- **CVE Data**: 
  - [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities)
  - [CVE-Search API](https://cve.circl.lu/)

- **Security News**:
  - [NewsAPI](https://newsapi.org/) with security keywords
  - RSS feeds from security blogs

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NIST NVD** - CVE data source
- **Font Awesome** - Beautiful icons
- **Security Community** - Continuous feedback and improvements

---

<div align="center">

**⭐ Star this repository if you found it helpful!**

[![GitHub stars](https://img.shields.io/github/stars/sivolko/cybersec-dashboard?style=social)](https://github.com/sivolko/cybersec-dashboard/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/sivolko/cybersec-dashboard?style=social)](https://github.com/sivolko/cybersec-dashboard/network)

Made with ❤️ by [Shubhendu Shubham](https://github.com/sivolko)

</div>