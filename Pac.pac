// Proxy Auto-Configuration (PAC) File

// Define proxy settings
var pass = "DIRECT";
var blackhole = "PROXY 127.0.0.1:65535";

// Enable or disable the proxy rules
var isEnabled = true;

// Whitelist domains to bypass proxy rules
var whitelist = [
    // Add whitelisted domains here, e.g., "example.com"
];

// Define blocked URLs (exact matches or specific patterns)
var blockedURLs = [
    // Add specific URL patterns to block
];

// Define blocked sites (exact domain matches)
var blockedSites = [
    "instrumenttactics.com",
    "srce.unizg.hr",
    "rtl.hr",
    "hrt.hr",
    "dnevnik.hr",
    "novatv.dnevnik.hr",
    "novavideo.dnevnik.hr",
    "forum.hr",
    "forum.pcekspert.com",
    "reddit.com/r/askcroatia",
    "reddit.com/r/croatia",
    "reddit.com/r/hrvatska",
    "discord.com/channels/889102180332732436",
    "discord.com/channels/452237221840551938",
    "discord.com/channels/1128414431085346897",
    "discord.com/channels/567592181905489920",
    "discord.com/channels/549448381613998103",
    "discord.com/channels/150662382874525696",
    "discord.com/channels/731641286389661727",
    "discord.com/channels/246414844851519490",
    "discord.com/channels/240880736851329024",
    "discord.com/channels/549448381613998103",
];

];

// Define blocked IPs
var blockedIPs = [
    "10.10.10.10",
    // Add more IPs as needed
];

// Define blocked IP ranges using CIDR notation
var blockedIPRanges = [
    { base: "10.0.0.0", mask: 8 }, // Blocks 10.0.0.0 - 10.255.255.255
    // Add more ranges as needed
];

// Define ad-related regex for blocking advertisements
var adRegex = /(^|\.)ads?\./i;

// Function to convert IP to numerical value
function ipToNum(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0);
}

// Function to check if IP is within a specified CIDR range
function isIPInRange(ip, range) {
    const ipNum = ipToNum(ip);
    const baseNum = ipToNum(range.base);
    const mask = 0xFFFFFFFF << (32 - range.mask);
    return (ipNum & mask) === (baseNum & mask);
}

// Function to validate IPv4 address
function isIPAddress(host) {
    var ipRegex = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
    return ipRegex.test(host);
}

// Core PAC function
function FindProxyForURL(url, host) {
    // Normalize inputs to lowercase for case-insensitive comparison
    host = host.toLowerCase();
    url = url.toLowerCase();

    // If proxy rules are disabled, allow direct connection
    if (!isEnabled) {
        return pass;
    }

    // If the host is in the whitelist, allow direct connection
    if (whitelist.length > 0 && whitelist.includes(host)) {
        return pass;
    }

    // Check against blocked URLs
    for (var i = 0; i < blockedURLs.length; i++) {
        if (url.includes(blockedURLs[i])) {
            return blackhole;
        }
    }

    // Check against blocked sites
    for (var i = 0; i < blockedSites.length; i++) {
        if (host === blockedSites[i] || host.endsWith('.' + blockedSites[i])) {
            return blackhole;
        }
    }

    // Check against blocked IPs
    if (isIPAddress(host)) {
        // Direct IP match
        if (blockedIPs.includes(host)) {
            return blackhole;
        }

        // Check IP ranges
        for (var i = 0; i < blockedIPRanges.length; i++) {
            if (isIPInRange(host, blockedIPRanges[i])) {
                return blackhole;
            }
        }
    }

    // Check against advertisement-related hosts
    if (adRegex.test(host)) {
        return blackhole;
    }

    // Optionally, resolve the host to IP and check additional IP ranges
    var ip = dnsResolve(host);
    if (ip && isIPAddress(ip)) {
        for (var i = 0; i < blockedIPRanges.length; i++) {
            if (isIPInRange(ip, blockedIPRanges[i])) {
                return blackhole;
            }
        }
    }

    // If none of the rules match, allow direct connection
    return pass;
}
