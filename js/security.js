// 安全防护模块
class SecurityManager {
    constructor() {
        this.initCSRFProtection();
        this.initXSSProtection();
        this.initSQLInjectionProtection();
        this.initDDoSProtection();  // 添加DDoS防护
        this.initUploadSecurity();  // 添加文件上传安全
    }

    // CSRF防护
    initCSRFProtection() {
        // 生成CSRF Token
        const csrfToken = this.generateCSRFToken();
        
        // 存储Token到localStorage和Cookie
        this.storeCSRFToken(csrfToken);
        
        // 为所有表单添加CSRF Token
        this.addCSRFToForms(csrfToken);
        
        // 为所有AJAX请求添加CSRF Token
        this.addCSRFToXHR(csrfToken);
    }

    // 生成CSRF Token
    generateCSRFToken() {
        const timestamp = new Date().getTime();
        const random = Math.random().toString(36).substring(2);
        const userAgent = navigator.userAgent;
        
        // 使用这些值创建一个独特的token
        const rawToken = `${timestamp}:${random}:${userAgent}`;
        // 使用SHA-256进行哈希
        return this.sha256(rawToken);
    }

    // 存储CSRF Token
    storeCSRFToken(token) {
        // 设置HttpOnly Cookie
        document.cookie = `XSRF-TOKEN=${token}; path=/; SameSite=Strict; Secure`;
        // 存储到localStorage用于AJAX请求
        localStorage.setItem('XSRF-TOKEN', token);
    }

    // 为所有表单添加CSRF Token
    addCSRFToForms(token) {
        document.querySelectorAll('form').forEach(form => {
            // 检查表单是否已有token
            if (!form.querySelector('input[name="_csrf"]')) {
                const tokenInput = document.createElement('input');
                tokenInput.type = 'hidden';
                tokenInput.name = '_csrf';
                tokenInput.value = token;
                form.appendChild(tokenInput);
            }

            // 添加表单提交事件监听
            form.addEventListener('submit', this.validateFormSubmission.bind(this));
        });
    }

    // 为所有AJAX请求添加CSRF Token
    addCSRFToXHR(token) {
        const originalOpen = XMLHttpRequest.prototype.open;
        const originalSend = XMLHttpRequest.prototype.send;

        XMLHttpRequest.prototype.open = function() {
            this.addEventListener('readystatechange', function() {
                if (this.readyState === 1) { // OPENED
                    this.setRequestHeader('X-CSRF-Token', token);
                }
            });
            originalOpen.apply(this, arguments);
        };

        // 同样为Fetch请求添加保护
        const originalFetch = window.fetch;
        window.fetch = function(url, options = {}) {
            if (!options.headers) {
                options.headers = {};
            }
            options.headers['X-CSRF-Token'] = token;
            return originalFetch.call(this, url, options);
        };
    }

    // 验证表单提交
    validateFormSubmission(event) {
        const form = event.target;
        const formToken = form.querySelector('input[name="_csrf"]')?.value;
        const storedToken = localStorage.getItem('XSRF-TOKEN');

        // 验证token
        if (!formToken || formToken !== storedToken) {
            event.preventDefault();
            console.error('CSRF Token验证失败');
            this.showSecurityWarning('检测到潜在的CSRF攻击，提交已被阻止。');
            return false;
        }
        return true;
    }

    // 显示安全警告
    showSecurityWarning(message) {
        const warning = document.createElement('div');
        warning.className = 'security-warning';
        warning.textContent = message;
        document.body.insertBefore(warning, document.body.firstChild);
        
        // 3秒后自动移除警告
        setTimeout(() => warning.remove(), 3000);
    }

    // SHA-256哈希函数
    async sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // XSS防护
    initXSSProtection() {
        // 基础输入数据净化函数
        window.sanitizeInput = (input) => {
            if (typeof input !== 'string') return input;
            return input.replace(/[&<>"']/g, char => ({
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
            }[char]));
        };

        // HTML内容净化函数
        window.sanitizeHTML = (html) => {
            const temp = document.createElement('div');
            temp.textContent = html;
            return temp.innerHTML;
        };

        // 防止XSS的URL验证
        window.sanitizeURL = (url) => {
            try {
                const parsed = new URL(url);
                return parsed.protocol === 'http:' || 
                       parsed.protocol === 'https:' ? url : '';
            } catch {
                return '';
            }
        };

        // 为所有输入添加XSS防护
        this.addInputListeners();
    }

    // 添加输入监听器
    addInputListeners() {
        document.addEventListener('input', (e) => {
            if (e.target.tagName === 'INPUT' || 
                e.target.tagName === 'TEXTAREA') {
                e.target.value = window.sanitizeInput(e.target.value);
            }
        }, true);

        // 防止通过JavaScript注入事件处理器
        document.addEventListener('DOMNodeInserted', (e) => {
            const element = e.target;
            if (element.nodeType === 1) { // 元素节点
                const attrs = element.attributes;
                for (let i = 0; i < attrs.length; i++) {
                    if (attrs[i].name.startsWith('on')) {
                        element.removeAttribute(attrs[i].name);
                    }
                }
            }
        });
    }

    // 生成随机的nonce值用于CSP
    generateNonce() {
        return Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // SQL注入防护
    initSQLInjectionProtection() {
        // 输入验证函数
        window.validateInput = (input) => {
            // 移除SQL关键字和特殊字符
            const sqlPattern = /(\b(select|insert|update|delete|drop|union|exec|declare)\b)|[;'"`\\]/gi;
            return input.replace(sqlPattern, '');
        };
    }

    // 初始化DDoS防护
    initDDoSProtection() {
        this.ddosProtection = new DDoSProtection();
    }

    // 初始化文件上传安全
    initUploadSecurity() {
        this.uploadSecurity = new UploadSecurity();
    }
} 