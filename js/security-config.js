// 全局安全配置
const SecurityConfig = {
    // HTTPS配置
    https: {
        enabled: true,
        cert: '/path/to/ssl/cert.pem',
        key: '/path/to/ssl/key.pem',
        options: {
            minVersion: 'TLSv1.2',
            ciphers: 'HIGH:!aNULL:!MD5'
        }
    },

    // 输入验证配置
    inputValidation: {
        maxLength: 1000,
        sanitizeInput: true,
        allowedTags: ['p', 'br', 'b', 'i', 'u'],
        allowedAttributes: ['href', 'title', 'target'],
        validatePatterns: {
            email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            phone: /^\+?[\d\s-]{10,}$/,
            url: /^https?:\/\/[\w\-]+(\.[\w\-]+)+[/#?]?.*$/
        }
    },

    // XSS防护配置
    xss: {
        enabled: true,
        sanitize: true,
        contentSecurityPolicy: {
            'default-src': ["'self'"],
            'script-src': ["'self'"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", 'data:', 'https:'],
            'connect-src': ["'self'"]
        }
    },

    // CSRF防护配置
    csrf: {
        enabled: true,
        tokenLength: 32,
        cookieOptions: {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict'
        },
        excludePaths: ['/api/public']
    },

    // DDoS防护配置
    ddos: {
        enabled: true,
        rateLimit: {
            windowMs: 15 * 60 * 1000, // 15分钟
            max: 100 // 每IP最大请求数
        },
        blacklist: [],
        whitelist: ['127.0.0.1'],
        blockDuration: 24 * 60 * 60 * 1000 // 24小时
    },

    // 文件上传配置
    upload: {
        enabled: true,
        maxFileSize: 10 * 1024 * 1024, // 10MB
        allowedTypes: [
            'image/jpeg',
            'image/png',
            'image/gif',
            'application/pdf'
        ],
        storageLocation: '/secure/uploads',
        scanVirus: true,
        validateContent: true
    },

    // 访问控制配置
    accessControl: {
        enabled: true,
        adminIPs: ['192.168.1.0/24'],
        sessionTimeout: 30 * 60, // 30分钟
        maxLoginAttempts: 5,
        lockoutDuration: 30 * 60, // 30分钟
        requireMFA: true
    },

    // 日志配置
    logging: {
        enabled: true,
        level: 'info',
        logPath: '/var/log/webapp',
        rotate: {
            size: '10M',
            keep: 10,
            compress: true
        },
        fields: [
            'timestamp',
            'ip',
            'method',
            'url',
            'status',
            'userAgent',
            'responseTime'
        ]
    },

    // 备份配置
    backup: {
        enabled: true,
        schedule: '0 0 * * *', // 每天凌晨
        retention: 30, // 保留30天
        location: '/backup',
        encrypt: true,
        compress: true,
        notify: true
    },

    // 监控配置
    monitoring: {
        enabled: true,
        checkInterval: 5 * 60 * 1000, // 5分钟
        metrics: [
            'cpu',
            'memory',
            'disk',
            'network',
            'requests',
            'errors'
        ],
        alertThresholds: {
            cpu: 80,
            memory: 85,
            disk: 90,
            errorRate: 5
        },
        notifications: {
            email: 'admin@example.com',
            slack: 'webhook_url'
        }
    },

    // 安全扫描配置
    securityScan: {
        enabled: true,
        schedule: '0 0 * * 0', // 每周日
        scanTypes: [
            'vulnerability',
            'malware',
            'configuration',
            'ssl'
        ],
        autoFix: true,
        reportPath: '/var/log/security'
    }
};

// 导出配置
module.exports = SecurityConfig; 