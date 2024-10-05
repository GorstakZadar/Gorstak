var pass = "DIRECT";
var blackhole = "PROXY 127.0.0.1:3421"; // Blackhole proxy to block traffic
var isEnabled = 1; // Toggle to enable or disable the PAC script
var whitelist = []; // Hosts to bypass the PAC script

var adRegex = new RegExp(
  "^(.+[-_.])?(ads?|teads|doubleclick|adservice|adtracker(?:er|ing)?|advertising|adnxs|admeld|advert|adx(?:addy|pose|pr[io])?|adform|admulti|adbutler|adblade|adroll|adgr(?:ao|interax)|admarvel|admed(?:ia|ix)|adperium|adplugg|adserver|adsolut|adtegr(?:it|ity)|adtraxx|affiliates?|akamaihd|amazon-adsystem|appnexus|appsflyer|audience2media|bingads|bidswitch|brightcove|casalemedia|contextweb|criteo|emxdgt|e-planning|exelator|eyewonder|flashtalking|google(?:syndication|tagservices)|gunggo|hurra(?:h|ynet)|imrworldwide|insightexpressai|kontera|lifestreetmedia|lkntracker|mediaplex|ooyala|openx|pixel(?:e|junky)|popcash|propellerads|pubmatic|quantserve|revcontent|revenuehits|sharethrough|skimresources|taboola|traktrafficx|twitter\\.com|undertone|yieldmo)",
  "i"
);

// Define blocked URLs (exact matches)
var blockedURLs = [
  "discord.com/channels/889102180332732436",
  "discord.com/channels/452237221840551938",
  "discord.com/channels/1128414431085346897",
  "discord.com/channels/567592181905489920",
  "discord.com/channels/549448381613998103",
  "discord.com/channels/150662382874525696",
  "discord.com/channels/731641286389661727",
  "discord.com/channels/246414844851519490",
  "discord.com/channels/240880736851329024",
  "reddit.com/r/croatia",
  "reddit.com/r/hrvatska"
  // Ensure no duplicate entries
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
  "forum.pcekspert.com"
  // Ensure no path-specific entries
];

// Define blocked IP ranges
var blockedIPRanges = [
  { base: "192.168.0.0", mask: 16 }, // 192.168.0.0/16
  { base: "10.0.0.0", mask: 8 }      // 10.0.0.0/8
  // Add more ranges as needed
];

// Convert IP address to a numerical value
function ipToNum(ip) {
  var parts = ip.split('.');
  return ((parseInt(parts[0], 10) << 24) |
          (parseInt(parts[1], 10) << 16) |
          (parseInt(parts[2], 10) << 8) |
          parseInt(parts[3], 10)) >>> 0;
}

// Check if an IP is within a specified range
function isIPInRange(ip, range) {
  var ipNum = ipToNum(ip);
  var baseNum = ipToNum(range.base);
  var mask = (0xFFFFFFFF << (32 - range.mask)) >>> 0;

  return (ipNum & mask) === (baseNum & mask);
}

// Validate if the host is an IP address
function isIPAddress(host) {
  var ipRegex = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/;
  return ipRegex.test(host);
}

// Extract the path from the URL
function getPath(url) {
  var pathStart = url.indexOf('/', url.indexOf('//') + 2);
  if (pathStart === -1) {
    return '/';
  }
  return url.substring(pathStart);
}

function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  url = url.toLowerCase();

  if (!isEnabled) {
    return pass;
  }

  // Check whitelist
  if (whitelist.length > 0) {
    for (var i = 0; i < whitelist.length; i++) {
      if (host === whitelist[i]) {
        return pass;
      }
    }
  }

  // Check blocked URLs
  for (var i = 0; i < blockedURLs.length; i++) {
    var blockedURL = blockedURLs[i];
    var blockedHost = blockedURL.split('/')[0];
    var blockedPath = blockedURL.substring(blockedURL.indexOf('/') || 0);

    if (host === blockedHost) {
      var urlPath = getPath(url);
      if (urlPath === blockedPath || url === blockedURL) {
        return blackhole;
      }
    }
  }

  // Check blocked sites
  for (var i = 0; i < blockedSites.length; i++) {
    var blockedSite = blockedSites[i];
    // Exact match or subdomain match
    if (host === blockedSite || host.indexOf('.' + blockedSite) === (host.length - blockedSite.length - 1)) {
      return blackhole;
    }
  }

  // Check blocked IP ranges
  if (isIPAddress(host)) {
    for (var i = 0; i < blockedIPRanges.length; i++) {
      if (isIPInRange(host, blockedIPRanges[i])) {
        return blackhole;
      }
    }
  }

  // Check ad-related domains
  if (adRegex.test(host)) {
    return blackhole;
  }

  return pass;
}
