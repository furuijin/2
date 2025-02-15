const SecurityConfig = require('./security-config');

class SecurityMiddleware {
    constructor() {
        this.config = SecurityConfig;
        this.initializeMiddlewares();
    }

    initializeMiddlewares() {
        this.initSecureHeaders();
        this.initSilentProtection();
        this.initErrorHandler();
    }

    // 初始化安全响应头（不显示服务器信息）
    initSecureHeaders() {
        return (req, res, next) => {
            // 移除所有可能暴露服务器信息的头部
            res.removeHeader('X-Powered-By');
            res.removeHeader('Server');
            res.removeHeader('X-AspNet-Version');
            res.removeHeader('X-AspNetMvc-Version');
            
            // 设置安全头部但不显示具体配置
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-Frame-Options', 'SAMEORIGIN');
            res.setHeader('Strict-Transport-Security', 'max-age=31536000');
            
            // 自定义错误页面
            res.setHeader('X-Custom-Error-Pages', 'true');
            
            next();
        };
    }

    // 静默保护（不显示安全提示）
    initSilentProtection() {
        return (req, res, next) => {
            // 请求验证
            this.validateRequest(req);
            
            // 内容过滤
            this.filterContent(req);
            
            // 访问控制
            this.controlAccess(req);
            
            next();
        };
    }

    // 自定义错误处理（显示友好的错误页面）
    initErrorHandler() {
        return (err, req, res, next) => {
            // 根据错误类型返回友好的错误页面
            switch(err.type) {
                case 'validation':
                    res.redirect('/friendly-error');
                    break;
                case 'auth':
                    res.redirect('/login');
                    break;
                case 'notfound':
                    res.redirect('/404');
                    break;
                default:
                    res.redirect('/error');
            }
        };
    }

    // 请求验证（静默）
    validateRequest(req) {
        // 验证请求但不显示具体原因
        if (!this.isValidRequest(req)) {
            return this.handleInvalidRequest(req);
        }
    }

    // 内容过滤（静默）
    filterContent(req) {
        // 过滤内容但不提示具体原因
        if (req.body) {
            req.body = this.sanitizeContent(req.body);
        }
    }

    // 访问控制（静默）
    controlAccess(req) {
        // 控制访问但不显示具体原因
        if (!this.isAllowedAccess(req)) {
            return this.handleUnauthorizedAccess(req);
        }
    }

    // 自定义错误页面
    createErrorPages() {
        const errorPages = {
            404: {
                title: '页面未找到',
                message: '您访问的页面不存在',
                suggestion: '请返回首页'
            },
            403: {
                title: '访问受限',
                message: '请稍后再试',
                suggestion: '返回首页继续浏览'
            },
            500: {
                title: '系统维护中',
                message: '请稍后访问',
                suggestion: '我们正在进行系统优化'
            }
        };

        return errorPages;
    }
}

// 创建友好的错误页面模板
const errorTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{title}}</title>
    <style>
        .error-container {
            text-align: center;
            padding: 50px;
            font-family: Arial, sans-serif;
        }
        .error-title {
            font-size: 24px;
            color: #333;
        }
        .error-message {
            font-size: 18px;
            color: #666;
            margin: 20px 0;
        }
        .back-button {
            padding: 10px 20px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1 class="error-title">{{title}}</h1>
        <p class="error-message">{{message}}</p>
        <p>{{suggestion}}</p>
        <a href="/" class="back-button">返回首页</a>
    </div>
</body>
</html>
`;

module.exports = SecurityMiddleware; 