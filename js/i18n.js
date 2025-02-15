// 语言配置
const translations = {
    zh: {
        nav: {
            home: '首页',
            about: '关于我们',
            services: '我们的服务',
            careers: '职业发展',
            contact: '联系我们',
            jobs: '招聘信息'
        }
        // 其他中文翻译...
    },
    en: {
        nav: {
            home: 'Home',
            about: 'About Us',
            services: 'Our Services',
            careers: 'Careers',
            contact: 'Contact Us',
            jobs: 'Jobs'
        }
        // 其他英文翻译...
    },
    ja: {
        nav: {
            home: 'ホーム',
            about: '会社概要',
            services: 'サービス',
            careers: 'キャリア',
            contact: 'お問い合わせ',
            jobs: '採用情報'
        }
        // 其他日语翻译...
    },
    ko: {
        nav: {
            home: '홈',
            about: '회사 소개',
            services: '서비스',
            careers: '경력 개발',
            contact: '문의하기',
            jobs: '채용 정보'
        }
        // 其他韩语翻译...
    }
};

// 切换语言函数
function changeLanguage(lang) {
    document.documentElement.lang = lang;
    const elements = document.querySelectorAll('[data-i18n]');
    
    elements.forEach(element => {
        const keys = element.getAttribute('data-i18n').split('.');
        let value = translations[lang];
        keys.forEach(key => {
            value = value[key];
        });
        element.textContent = value;
    });

    // 保存语言选择
    localStorage.setItem('preferred-language', lang);
}

// 页面加载时初始化语言
document.addEventListener('DOMContentLoaded', () => {
    const savedLang = localStorage.getItem('preferred-language') || 'zh';
    changeLanguage(savedLang);
    document.getElementById('langSelect').value = savedLang;
}); 