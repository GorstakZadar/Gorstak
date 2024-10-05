var pass = "DIRECT";
var blackhole = "PROXY 127.0.0.1:3421";
var isEnabled = 1;

// Using Sets for efficient lookups
var whitelist = new Set([
  // Add whitelisted hosts here
]);

var blockedURLs = new Set([
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
]);

var blockedSites = new Set([
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
]);

var blockedCIDRs = [
  "192.168.0.0/16",
  "10.0.0.0/8"
  // Add more CIDR notations as needed
];

// Convert CIDR to range
function cidrToRange(cidr) {
  const [base, mask] = cidr.split('/');
  const baseNum = ipToNum(base);
  const maskBits = parseInt(mask, 10);
  const maskValue = maskBits === 0 ? 0 : (0xFFFFFFFF << (32 - maskBits)) >>> 0;
  return { baseNum, mask: maskValue };
}

var blockedRanges = blockedCIDRs.map(cidr => cidrToRange(cidr));

function ipToNum(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function isIPInBlockedRanges(ip) {
  const ipNum = ipToNum(ip);
  return blockedRanges.some(range => (ipNum & range.mask) === (range.baseNum & range.mask));
}

function isIPAddress(host) {
  var ipRegex = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/;
  return ipRegex.test(host);
}

var adDomains = [
  "ads?", "teads", "doubleclick", "adservice", "adtracker(?:er|ing)?",
  "advertising", "adnxs", "admeld", "advert", "adx(?:addy|pose|pr[io])?",
  "adform", "admulti", "adbutler", "adblade", "adroll", "adgr(?:ao|interax)",
  "admarvel", "admed(?:ia|ix)", "adperium", "adplugg", "adserver",
  "adsolut", "adtegr(?:it|ity)", "adtraxx", "affiliates?", "akamaihd",
  "amazon-adsystem", "appnexus", "appsflyer", "audience2media", "bingads",
  "bidswitch", "brightcove", "casalemedia", "contextweb", "criteo",
  "emxdgt", "e-planning", "exelator", "eyewonder", "flashtalking",
  "google(?:syndication|tagservices)", "gunggo", "hurra(?:h|ynet)",
  "imrworldwide", "insightexpressai", "kontera", "lifestreetmedia",
  "lkntracker", "mediaplex", "ooyala", "openx", "pixel(?:e|junky)",
  "popcash", "propellerads", "pubmatic", "quantserve", "revcontent",
  "revenuehits", "sharethrough", "skimresources", "taboola",
  "traktrafficx", "twitter\\.com", "undertone", "yieldmo"
].join("|");

var adRegex = new RegExp(`^(?:.+[-_.])?(?:${adDomains})$`, "i");

function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  url = url.toLowerCase();

  if (!isEnabled) {
    // Optionally log this action
    return pass;
  }

  if (whitelist.has(host)) {
    // Optionally log this action
    return pass;
  }

  if (blockedURLs.has(url) || blockedURLs.has(host)) {
    // Optionally log this action
    return blackhole;
  }

  if (blockedSites.has(host) || Array.from(blockedSites).some(site => url.startsWith(`${site}/`))) {
    // Optionally log this action
    return blackhole;
  }

  if (isIPAddress(host) && isIPInBlockedRanges(host)) {
    // Optionally log this action
    return blackhole;
  }

  if (adRegex.test(host)) {
    // Optionally log this action
    return blackhole;
  }

  // Optionally log this action
  return pass;
}
