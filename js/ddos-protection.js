// DDoS防护模块
class DDoSProtection {
    constructor() {
        // 初始化配置
        this.config = {
            maxRequestsPerMinute: 60,    // 每分钟最大请求数
            maxConnectionsPerIP: 10,     // 每IP最大并发连接数
            blockDuration: 300000,       // 封禁时长（5分钟）
            whitelist: new Set(),        // IP白名单
            blacklist: new Set()         // IP黑名单
        };

        // 请求计数器
        this.requestCounts = new Map();  // IP -> 请求数
        this.connections = new Map();    // IP -> 连接数
        this.lastReset = Date.now();     // 上次重置计数器的时间

        // 初始化防护
        this.initProtection();
    }

    // 初始化防护措施
    initProtection() {
        // 定期重置计数器
        setInterval(() => this.resetCounters(), 60000);
        
        // 监听请求
        this.addRequestListener();
        
        // 添加速率限制中间件
        this.addRateLimiting();
    }

    // 添加请求监听
    addRequestListener() {
        document.addEventListener('fetch', (event) => {
            const clientIP = this.getClientIP();
            
            // 检查IP是否在黑名单中
            if (this.isBlacklisted(clientIP)) {
                this.blockRequest(event);
                return;
            }

            // 更新请求计数
            this.updateRequestCount(clientIP);

            // 检查是否超过限制
            if (this.isRateExceeded(clientIP)) {
                this.handleExcessiveRequests(clientIP, event);
                return;
            }
        });
    }

    // 添加速率限制
    addRateLimiting() {
        const originalFetch = window.fetch;
        window.fetch = async (url, options = {}) => {
            const clientIP = this.getClientIP();
            
            // 检查连接数限制
            if (this.connections.get(clientIP) >= this.config.maxConnectionsPerIP) {
                throw new Error('已超过最大并发连接数限制');
            }

            // 增加连接计数
            this.incrementConnections(clientIP);

            try {
                // 添加防护头部
                options.headers = {
                    ...options.headers,
                    'X-Request-ID': this.generateRequestId(),
                    'X-Rate-Limit-Remaining': this.getRemainingRequests(clientIP)
                };

                return await originalFetch(url, options);
            } finally {
                // 减少连接计数
                this.decrementConnections(clientIP);
            }
        };
    }

    // 更新请求计数
    updateRequestCount(ip) {
        const count = this.requestCounts.get(ip) || 0;
        this.requestCounts.set(ip, count + 1);
    }

    // 检查是否超过速率限制
    isRateExceeded(ip) {
        const count = this.requestCounts.get(ip) || 0;
        return count > this.config.maxRequestsPerMinute;
    }

    // 处理过量请求
    handleExcessiveRequests(ip, event) {
        // 记录可疑IP
        this.logSuspiciousActivity(ip);
        
        // 如果持续超限，加入黑名单
        if (this.shouldBlacklist(ip)) {
            this.blacklist.add(ip);
            setTimeout(() => this.blacklist.delete(ip), this.config.blockDuration);
        }

        // 返回429状态码
        event.respondWith(
            new Response('Too Many Requests', {
                status: 429,
                headers: {
                    'Retry-After': '60',
                    'X-RateLimit-Reset': this.getResetTime()
                }
            })
        );
    }

    // 生成请求ID
    generateRequestId() {
        return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }

    // 获取剩余请求数
    getRemainingRequests(ip) {
        const count = this.requestCounts.get(ip) || 0;
        return Math.max(0, this.config.maxRequestsPerMinute - count);
    }

    // 重置计数器
    resetCounters() {
        const now = Date.now();
        if (now - this.lastReset >= 60000) {
            this.requestCounts.clear();
            this.lastReset = now;
        }
    }

    // 增加连接计数
    incrementConnections(ip) {
        const count = this.connections.get(ip) || 0;
        this.connections.set(ip, count + 1);
    }

    // 减少连接计数
    decrementConnections(ip) {
        const count = this.connections.get(ip) || 1;
        this.connections.set(ip, count - 1);
    }

    // 记录可疑活动
    logSuspiciousActivity(ip) {
        console.warn(`可疑活动: IP ${ip} 请求过于频繁`);
        // 这里可以添加日志记录或告警通知
    }

    // 检查是否应该加入黑名单
    shouldBlacklist(ip) {
        const count = this.requestCounts.get(ip) || 0;
        return count > this.config.maxRequestsPerMinute * 2;
    }

    // 获取重置时间
    getResetTime() {
        return new Date(this.lastReset + 60000).toISOString();
    }

    // 获取客户端IP（实际实现需要后端支持）
    getClientIP() {
        // 这里需要配合后端实现
        return 'client-ip';
    }
} 