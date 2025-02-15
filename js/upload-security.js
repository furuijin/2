// 文件上传安全模块
class UploadSecurity {
    constructor() {
        // 初始化配置
        this.config = {
            // 允许的文件类型
            allowedTypes: new Set([
                'image/jpeg',
                'image/png',
                'image/gif',
                'application/pdf',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            ]),
            maxFileSize: 10 * 1024 * 1024, // 10MB
            virusScanEndpoint: '/api/security/scan',
            quarantineFolder: '/quarantine/'
        };

        // 初始化防护
        this.initUploadProtection();
    }

    // 初始化上传防护
    initUploadProtection() {
        // 监听所有文件上传
        document.addEventListener('change', (event) => {
            if (event.target.type === 'file') {
                this.validateFileUpload(event.target);
            }
        });

        // 防止拖拽上传
        document.addEventListener('dragover', (e) => e.preventDefault());
        document.addEventListener('drop', (e) => {
            e.preventDefault();
            this.handleDroppedFiles(e.dataTransfer.files);
        });
    }

    // 验证文件上传
    async validateFileUpload(fileInput) {
        const files = fileInput.files;
        const validationResults = [];

        for (let file of files) {
            try {
                // 基础验证
                await this.performBasicValidation(file);
                
                // 内容验证
                await this.validateFileContent(file);
                
                // 病毒扫描
                const scanResult = await this.scanFile(file);
                
                if (scanResult.safe) {
                    validationResults.push({
                        file: file.name,
                        status: 'valid',
                        message: '文件验证通过'
                    });
                } else {
                    this.quarantineFile(file);
                    throw new Error('检测到潜在威胁');
                }
            } catch (error) {
                validationResults.push({
                    file: file.name,
                    status: 'invalid',
                    message: error.message
                });
                
                // 移除不安全的文件
                this.removeFile(fileInput, file);
            }
        }

        this.displayValidationResults(validationResults);
    }

    // 基础文件验证
    async performBasicValidation(file) {
        // 检查文件类型
        if (!this.config.allowedTypes.has(file.type)) {
            throw new Error('不支持的文件类型');
        }

        // 检查文件大小
        if (file.size > this.config.maxFileSize) {
            throw new Error('文件大小超过限制');
        }

        // 检查文件名安全性
        if (!this.isFileNameSafe(file.name)) {
            throw new Error('文件名包含不安全字符');
        }

        // 检查文件头
        await this.validateFileHeader(file);
    }

    // 验证文件内容
    async validateFileContent(file) {
        // 读取文件内容
        const content = await this.readFileContent(file);

        // 检查恶意代码特征
        if (this.containsMaliciousCode(content)) {
            throw new Error('检测到潜在的恶意代码');
        }

        // 检查文件完整性
        if (!await this.verifyFileIntegrity(file)) {
            throw new Error('文件完整性验证失败');
        }
    }

    // 扫描文件病毒
    async scanFile(file) {
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(this.config.virusScanEndpoint, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('病毒扫描服务异常');
            }

            return await response.json();
        } catch (error) {
            console.error('病毒扫描失败:', error);
            throw new Error('无法完成病毒扫描');
        }
    }

    // 检查文件名安全性
    isFileNameSafe(fileName) {
        // 禁止特殊字符和路径遍历
        const unsafePattern = /[<>:"/\\|?*\x00-\x1F]|\.\.|\s+$/;
        return !unsafePattern.test(fileName);
    }

    // 验证文件头
    async validateFileHeader(file) {
        const headerBytes = await this.readFileHeader(file);
        const fileType = this.detectFileType(headerBytes);

        if (fileType !== file.type) {
            throw new Error('文件类型与扩展名不匹配');
        }
    }

    // 读取文件头部
    async readFileHeader(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const arr = new Uint8Array(e.target.result);
                resolve(arr.slice(0, 8)); // 读取前8字节
            };
            reader.onerror = reject;
            reader.readAsArrayBuffer(file.slice(0, 8));
        });
    }

    // 检查恶意代码特征
    containsMaliciousCode(content) {
        const maliciousPatterns = [
            /<script\b[^>]*>([\s\S]*?)<\/script>/gi,
            /eval\s*\(/gi,
            /execScript\s*\(/gi,
            /document\.write\s*\(/gi,
            /\.exe$/i,
            /\.dll$/i,
            /\.bat$/i,
            /\.cmd$/i,
            /\.sh$/i
        ];

        return maliciousPatterns.some(pattern => pattern.test(content));
    }

    // 验证文件完整性
    async verifyFileIntegrity(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(true);
            reader.onerror = () => resolve(false);
            reader.readAsArrayBuffer(file);
        });
    }

    // 隔离可疑文件
    quarantineFile(file) {
        // 在实际应用中，这里应该调用后端API来隔离文件
        console.warn(`文件 ${file.name} 已被隔离`);
    }

    // 移除不安全文件
    removeFile(fileInput, file) {
        const dt = new DataTransfer();
        const { files } = fileInput;

        for (let i = 0; i < files.length; i++) {
            if (files[i] !== file) {
                dt.items.add(files[i]);
            }
        }

        fileInput.files = dt.files;
    }

    // 显示验证结果
    displayValidationResults(results) {
        const container = document.createElement('div');
        container.className = 'validation-results';

        results.forEach(result => {
            const resultElement = document.createElement('div');
            resultElement.className = `validation-result ${result.status}`;
            resultElement.innerHTML = `
                <span class="file-name">${result.file}</span>
                <span class="message">${result.message}</span>
            `;
            container.appendChild(resultElement);
        });

        // 显示结果
        document.body.appendChild(container);
        setTimeout(() => container.remove(), 5000);
    }
} 