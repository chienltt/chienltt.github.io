import base64 from 'base64-js';
import sha256 from 'js-sha256';

function Keycloak(config) {

    let kc = this;
    let adapter;
    let refreshQueue = [];
    let callbackStorage;

    let loginIframe = {
        enable: true,
        callbackList: [],
        interval: 5
    };

    let scripts = document.getElementsByTagName('script');
    for (let i = 0; i < scripts.length; i++) {
        if ((scripts[i].src.indexOf('keycloak.js') !== -1 || scripts[i].src.indexOf('keycloak.min.js') !== -1) && scripts[i].src.indexOf('version=') !== -1) {
            kc.iframeVersion = scripts[i].src.substring(scripts[i].src.indexOf('version=') + 8).split('&')[0];
        }
    }

    let useNonce = true;
    let logInfo = createLogger(console.info);
    let logWarn = createLogger(console.warn);

    kc.init = function (initOptions) {

        kc.didInitialize = true;

        kc.authenticated = false;

        callbackStorage = createCallbackStorage();
        let adapters = ['default', 'cordova', 'cordova-native'];

        if (initOptions && adapters.indexOf(initOptions.adapter) > -1) {
            adapter = loadAdapter(initOptions.adapter);
        } else if (initOptions && typeof initOptions.adapter === "object") {
            adapter = initOptions.adapter;
        } else {
            if (window.Cordova || window.cordova) {
                adapter = loadAdapter('cordova');
            } else {
                adapter = loadAdapter();
            }
        }

        if (initOptions) {
            if (typeof initOptions.useNonce !== 'undefined') {
                useNonce = initOptions.useNonce;
            }

            if (typeof initOptions.checkLoginIframe !== 'undefined') {
                loginIframe.enable = initOptions.checkLoginIframe;
            }

            if (initOptions.checkLoginIframeInterval) {
                loginIframe.interval = initOptions.checkLoginIframeInterval;
            }

            if (initOptions.onLoad === 'login-required') {
                kc.loginRequired = true;
            }

            if (initOptions.responseMode) {
                if (initOptions.responseMode === 'query' || initOptions.responseMode === 'fragment') {
                    kc.responseMode = initOptions.responseMode;
                } else {
                    throw 'Invalid value for responseMode';
                }
            }

            if (initOptions.flow) {
                switch (initOptions.flow) {
                    case 'standard':
                        kc.responseType = 'code';
                        break;
                    case 'implicit':
                        kc.responseType = 'id_token token';
                        break;
                    case 'hybrid':
                        kc.responseType = 'code id_token token';
                        break;
                    default:
                        throw 'Invalid value for flow';
                }
                kc.flow = initOptions.flow;
            }

            if (initOptions.timeSkew != null) {
                kc.timeSkew = initOptions.timeSkew;
            }

            if (initOptions.redirectUri) {
                kc.redirectUri = initOptions.redirectUri;
            }

            if (initOptions.silentCheckSsoRedirectUri) {
                kc.silentCheckSsoRedirectUri = initOptions.silentCheckSsoRedirectUri;
            }

            if (typeof initOptions.silentCheckSsoFallback === 'boolean') {
                kc.silentCheckSsoFallback = initOptions.silentCheckSsoFallback;
            } else {
                kc.silentCheckSsoFallback = true;
            }

            if (initOptions.pkceMethod) {
                if (initOptions.pkceMethod !== "S256") {
                    throw 'Invalid value for pkceMethod';
                }
                kc.pkceMethod = initOptions.pkceMethod;
            }

            if (typeof initOptions.enableLogging === 'boolean') {
                kc.enableLogging = initOptions.enableLogging;
            } else {
                kc.enableLogging = false;
            }

            if (typeof initOptions.scope === 'string') {
                kc.scope = initOptions.scope;
            }

            if (typeof initOptions.messageReceiveTimeout === 'number' && initOptions.messageReceiveTimeout > 0) {
                kc.messageReceiveTimeout = initOptions.messageReceiveTimeout;
            } else {
                kc.messageReceiveTimeout = 10000;
            }
        }

        if (!kc.responseMode) {
            kc.responseMode = 'fragment';
        }
        if (!kc.responseType) {
            kc.responseType = 'code';
            kc.flow = 'standard';
        }

        let promise = createPromise();

        let initPromise = createPromise();
        initPromise.promise.then(function () {
            kc.onReady && kc.onReady(kc.authenticated);
            promise.setSuccess(kc.authenticated);
        }).catch(function (error) {
            promise.setError(error);
        });

        let configPromise = loadConfig();

        function onLoad() {
            let doLogin = function (prompt) {
                if (!prompt) {
                    options.prompt = 'none';
                }

                if (initOptions && initOptions.locale) {
                    options.locale = initOptions.locale;
                }
                kc.login(options).then(function () {
                    initPromise.setSuccess();
                }).catch(function (error) {
                    initPromise.setError(error);
                });
            };

            let checkSsoSilently = function () {
                let ifrm = document.createElement("iframe");
                let src = kc.createLoginUrl({prompt: 'none', redirectUri: kc.silentCheckSsoRedirectUri});
                ifrm.setAttribute("src", src);
                ifrm.setAttribute("sandbox", "allow-scripts allow-same-origin");
                ifrm.setAttribute("title", "keycloak-silent-check-sso");
                ifrm.style.display = "none";
                document.body.appendChild(ifrm);

                let messageCallback = function (event) {
                    if (event.origin !== window.location.origin || ifrm.contentWindow !== event.source) {
                        return;
                    }

                    let oauth = parseCallback(event.data);
                    processCallback(oauth, initPromise);

                    document.body.removeChild(ifrm);
                    window.removeEventListener("message", messageCallback);
                };

                window.addEventListener("message", messageCallback);
            };

            let options = {};
            switch (initOptions.onLoad) {
                case 'check-sso':
                    if (loginIframe.enable) {
                        setupCheckLoginIframe().then(function () {
                            checkLoginIframe().then(function (unchanged) {
                                if (!unchanged) {
                                    kc.silentCheckSsoRedirectUri ? checkSsoSilently() : doLogin(false);
                                } else {
                                    initPromise.setSuccess();
                                }
                            }).catch(function (error) {
                                initPromise.setError(error);
                            });
                        });
                    } else {
                        kc.silentCheckSsoRedirectUri ? checkSsoSilently() : doLogin(false);
                    }
                    break;
                case 'login-required':
                    doLogin(true);
                    break;
                default:
                    throw 'Invalid value for onLoad';
            }
        }

        function processInit() {
            let callback = parseCallback(window.location.href);

            if (callback) {
                window.history.replaceState(window.history.state, null, callback.newUrl);
            }

            if (callback && callback.valid) {
                return setupCheckLoginIframe().then(function () {
                    processCallback(callback, initPromise);
                }).catch(function (error) {
                    initPromise.setError(error);
                });
            } else if (initOptions) {
                if (initOptions.token && initOptions.refreshToken) {
                    setToken(initOptions.token, initOptions.refreshToken, initOptions.idToken);

                    if (loginIframe.enable) {
                        setupCheckLoginIframe().then(function () {
                            checkLoginIframe().then(function (unchanged) {
                                if (unchanged) {
                                    kc.onAuthSuccess && kc.onAuthSuccess();
                                    initPromise.setSuccess();
                                    scheduleCheckIframe();
                                } else {
                                    initPromise.setSuccess();
                                }
                            }).catch(function (error) {
                                initPromise.setError(error);
                            });
                        });
                    } else {
                        kc.updateToken(-1).then(function () {
                            kc.onAuthSuccess && kc.onAuthSuccess();
                            initPromise.setSuccess();
                        }).catch(function (error) {
                            kc.onAuthError && kc.onAuthError();
                            if (initOptions.onLoad) {
                                onLoad();
                            } else {
                                initPromise.setError(error);
                            }
                        });
                    }
                } else if (initOptions.onLoad) {
                    onLoad();
                } else {
                    initPromise.setSuccess();
                }
            } else {
                initPromise.setSuccess();
            }
        }

        function domReady() {
            let promise = createPromise();

            let checkReadyState = function () {
                if (document.readyState === 'interactive' || document.readyState === 'complete') {
                    document.removeEventListener('readystatechange', checkReadyState);
                    promise.setSuccess();
                }
            };
            document.addEventListener('readystatechange', checkReadyState);

            checkReadyState();

            return promise.promise;
        }

        configPromise.then(function () {
            domReady()
                .then(check3pCookiesSupported)
                .then(processInit)
                .catch(function (error) {
                    promise.setError(error);
                });
        });
        configPromise.catch(function (error) {
            promise.setError(error);
        });

        return promise.promise;
    };

    kc.login = function (options) {
        return adapter.login(options);
    };

    function generateRandomData(len) {
        let array;
        let crypto = window.crypto || window.msCrypto;
        if (crypto && crypto.getRandomValues && window.Uint8Array) {
            array = new Uint8Array(len);
            crypto.getRandomValues(array);
            return array;
        }

        array = new Array(len);
        for (let j = 0; j < array.length; j++) {
            array[j] = Math.floor(256 * Math.random());
        }
        return array;
    }

    function generateCodeVerifier(len) {
        return generateRandomString(len, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
    }

    function generateRandomString(len, alphabet) {
        let randomData = generateRandomData(len);
        let chars = new Array(len);
        for (let i = 0; i < len; i++) {
            chars[i] = alphabet.charCodeAt(randomData[i] % alphabet.length);
        }
        return String.fromCharCode.apply(null, chars);
    }

    function generatePkceChallenge(pkceMethod, codeVerifier) {
        switch (pkceMethod) {
            case "S256":
                let hashBytes = new Uint8Array(sha256.arrayBuffer(codeVerifier));
                let encodedHash = base64.fromByteArray(hashBytes)
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/\=/g, '');
                return encodedHash;
            default:
                throw 'Invalid value for pkceMethod';
        }
    }

    function buildClaimsParameter(requestedAcr) {
        let claims = {
            id_token: {
                acr: requestedAcr
            }
        };
        return JSON.stringify(claims);
    }

    kc.createLoginUrl = function (options) {
        let state = createUUID();
        let nonce = createUUID();

        let redirectUri = adapter.redirectUri(options);

        let callbackState = {
            state: state,
            nonce: nonce,
            redirectUri: encodeURIComponent(redirectUri)
        };

        if (options && options.prompt) {
            callbackState.prompt = options.prompt;
        }

        let baseUrl;
        if (options && options.action === 'register') {
            baseUrl = kc.endpoints.register();
        } else {
            baseUrl = kc.endpoints.authorize();
        }

        let scope = options && options.scope || kc.scope;
        if (!scope) {
            scope = "openid";
        } else if (scope.indexOf("openid") === -1) {
            scope = "openid " + scope;
        }

        let url = baseUrl
            + '?client_id=' + encodeURIComponent(kc.clientId)
            + '&redirect_uri=' + encodeURIComponent(redirectUri)
            + '&state=' + encodeURIComponent(state)
            + '&response_mode=' + encodeURIComponent(kc.responseMode)
            + '&response_type=' + encodeURIComponent(kc.responseType)
            + '&scope=' + encodeURIComponent(scope);
        if (useNonce) {
            url = url + '&nonce=' + encodeURIComponent(nonce);
        }

        if (options && options.prompt) {
            url += '&prompt=' + encodeURIComponent(options.prompt);
        }

        if (options && options.maxAge) {
            url += '&max_age=' + encodeURIComponent(options.maxAge);
        }

        if (options && options.loginHint) {
            url += '&login_hint=' + encodeURIComponent(options.loginHint);
        }

        if (options && options.idpHint) {
            url += '&kc_idp_hint=' + encodeURIComponent(options.idpHint);
        }

        if (options && options.action && options.action !== 'register') {
            url += '&kc_action=' + encodeURIComponent(options.action);
        }

        if (options && options.locale) {
            url += '&ui_locales=' + encodeURIComponent(options.locale);
        }

        if (options && options.acr) {
            let claimsParameter = buildClaimsParameter(options.acr);
            url += '&claims=' + encodeURIComponent(claimsParameter);
        }

        if (kc.pkceMethod) {
            let codeVerifier = generateCodeVerifier(96);
            callbackState.pkceCodeVerifier = codeVerifier;
            let pkceChallenge = generatePkceChallenge(kc.pkceMethod, codeVerifier);
            url += '&code_challenge=' + pkceChallenge;
            url += '&code_challenge_method=' + kc.pkceMethod;
        }

        callbackStorage.add(callbackState);

        return url;
    };

    kc.logout = function (options) {
        return adapter.logout(options);
    };

    kc.createLogoutUrl = function (options) {
        let url = kc.endpoints.logout()
            + '?client_id=' + encodeURIComponent(kc.clientId)
            + '&post_logout_redirect_uri=' + encodeURIComponent(adapter.redirectUri(options, false));

        if (kc.idToken) {
            url += '&id_token_hint=' + encodeURIComponent(kc.idToken);
        }

        return url;
    };

    kc.register = function (options) {
        return adapter.register(options);
    };

    kc.createRegisterUrl = function (options) {
        if (!options) {
            options = {};
        }
        options.action = 'register';
        return kc.createLoginUrl(options);
    };

    kc.createAccountUrl = function (options) {
        let realm = getRealmUrl();
        let url = undefined;
        if (typeof realm !== 'undefined') {
            url = realm
                + '/account'
                + '?referrer=' + encodeURIComponent(kc.clientId)
                + '&referrer_uri=' + encodeURIComponent(adapter.redirectUri(options));
        }
        return url;
    };

    kc.accountManagement = function () {
        return adapter.accountManagement();
    };

    kc.hasRealmRole = function (role) {
        let access = kc.realmAccess;
        return !!access && access.roles.indexOf(role) >= 0;
    };

    kc.hasResourceRole = function (role, resource) {
        if (!kc.resourceAccess) {
            return false;
        }

        let access = kc.resourceAccess[resource || kc.clientId];
        return !!access && access.roles.indexOf(role) >= 0;
    };

    kc.loadUserProfile = function () {
        let url = getRealmUrl() + '/account';
        let req = new XMLHttpRequest();
        req.open('GET', url, true);
        req.setRequestHeader('Accept', 'application/json');
        req.setRequestHeader('Authorization', 'bearer ' + kc.token);

        let promise = createPromise();

        req.onreadystatechange = function () {
            if (req.readyState === 4) {
                if (req.status === 200) {
                    kc.profile = JSON.parse(req.responseText);
                    promise.setSuccess(kc.profile);
                } else {
                    promise.setError();
                }
            }
        };

        req.send();

        return promise.promise;
    };

    kc.loadUserInfo = function () {
        let url = kc.endpoints.userinfo();
        let req = new XMLHttpRequest();
        req.open('GET', url, true);
        req.setRequestHeader('Accept', 'application/json');
        req.setRequestHeader('Authorization', 'bearer ' + kc.token);

        let promise = createPromise();

        req.onreadystatechange = function () {
            if (req.readyState === 4) {
                if (req.status === 200) {
                    kc.userInfo = JSON.parse(req.responseText);
                    promise.setSuccess(kc.userInfo);
                } else {
                    promise.setError();
                }
            }
        };

        req.send();

        return promise.promise;
    };

    kc.isTokenExpired = function (minValidity) {
        if (!kc.tokenParsed || (!kc.refreshToken && kc.flow !== 'implicit')) {
            throw 'Not authenticated';
        }

        if (kc.timeSkew == null) {
            return true;
        }

        let expiresIn = kc.tokenParsed['exp'] - Math.ceil(new Date().getTime() / 1000) + kc.timeSkew;
        if (minValidity) {
            if (isNaN(minValidity)) {
                throw 'Invalid minValidity';
            }
            expiresIn -= minValidity;
        }
        return expiresIn < 0;
    };

    kc.updateToken = function (minValidity) {
        let promise = createPromise();

        if (!kc.refreshToken) {
            promise.setError();
            return promise.promise;
        }

        minValidity = minValidity || 5;

        let exec = function () {
            let refreshToken = false;
            if (minValidity === -1) {
                refreshToken = true;
            } else if (!kc.tokenParsed || kc.isTokenExpired(minValidity)) {
                refreshToken = true;
            }

            if (!refreshToken) {
                promise.setSuccess(false);
            } else {
                let params = 'grant_type=refresh_token&' + 'refresh_token=' + kc.refreshToken;
                let url = kc.endpoints.token();

                refreshQueue.push(promise);

                if (refreshQueue.length === 1) {
                    let req = new XMLHttpRequest();
                    req.open('POST', url, true);
                    req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                    req.withCredentials = true;

                    params += '&client_id=' + encodeURIComponent(kc.clientId);

                    let timeLocal = new Date().getTime();

                    req.onreadystatechange = function () {
                        if (req.readyState === 4) {
                            if (req.status === 200) {
                                logInfo('[KEYCLOAK] Token refreshed');

                                timeLocal = (timeLocal + new Date().getTime()) / 2;

                                let tokenResponse = JSON.parse(req.responseText);

                                setToken(tokenResponse['access_token'], tokenResponse['refresh_token'], tokenResponse['id_token'], timeLocal);

                                kc.onAuthRefreshSuccess && kc.onAuthRefreshSuccess();
                                for (let p = refreshQueue.pop(); p !== null; p = refreshQueue.pop()) {
                                    p.setSuccess(true);
                                }
                            } else {
                                logWarn('[KEYCLOAK] Failed to refresh token');

                                if (req.status === 400) {
                                    kc.clearToken();
                                }

                                kc.onAuthRefreshError && kc.onAuthRefreshError();
                                for (let p = refreshQueue.pop(); p != null; p = refreshQueue.pop()) {
                                    p.setError(true);
                                }
                            }
                        }
                    };

                    req.send(params);
                }
            }
        };

        if (loginIframe.enable) {
            let iframePromise = checkLoginIframe();
            iframePromise.then(function () {
                exec();
            }).catch(function (error) {
                promise.setError(error);
            });
        } else {
            exec();
        }

        return promise.promise;
    };

    kc.clearToken = function () {
        if (kc.token) {
            setToken(null, null, null);
            kc.onAuthLogout && kc.onAuthLogout();
            if (kc.loginRequired) {
                kc.login();
            }
        }
    };

    function getRealmUrl() {
        if (typeof kc.authServerUrl !== 'undefined') {
            if (kc.authServerUrl.charAt(kc.authServerUrl.length - 1) === '/') {
                return kc.authServerUrl + 'realms/' + encodeURIComponent(kc.realm);
            } else {
                return kc.authServerUrl + '/realms/' + encodeURIComponent(kc.realm);
            }
        } else {
            return undefined;
        }
    }

    function getOrigin() {
        if (!window.location.origin) {
            return window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
        } else {
            return window.location.origin;
        }
    }

    function processCallback(oauth, promise) {
        let code = oauth.code;
        let error = oauth.error;
        let prompt = oauth.prompt;

        let timeLocal = new Date().getTime();

        if (oauth['kc_action_status']) {
            kc.onActionUpdate && kc.onActionUpdate(oauth['kc_action_status']);
        }

        if (error) {
            if (prompt !== 'none') {
                let errorData = {error: error, error_description: oauth.error_description};
                kc.onAuthError && kc.onAuthError(errorData);
                promise && promise.setError(errorData);
            } else {
                promise && promise.setSuccess();
            }
            return;
        } else if ((kc.flow !== 'standard') && (oauth.access_token || oauth.id_token)) {
            authSuccess(oauth.access_token, null, oauth.id_token, true);
        }

        if ((kc.flow !== 'implicit') && code) {
            let params = 'code=' + code + '&grant_type=authorization_code';
            let url = kc.endpoints.token();

            let req = new XMLHttpRequest();
            req.open('POST', url, true);
            req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

            params += '&client_id=' + encodeURIComponent(kc.clientId);
            params += '&redirect_uri=' + oauth.redirectUri;

            if (oauth.pkceCodeVerifier) {
                params += '&code_verifier=' + oauth.pkceCodeVerifier;
            }

            req.withCredentials = true;

            req.onreadystatechange = function () {
                if (req.readyState === 4) {
                    if (req.status === 200) {

                        let tokenResponse = JSON.parse(req.responseText);
                        authSuccess(tokenResponse['access_token'], tokenResponse['refresh_token'], tokenResponse['id_token'], kc.flow === 'standard');
                        scheduleCheckIframe();
                    } else {
                        kc.onAuthError && kc.onAuthError();
                        promise && promise.setError();
                    }
                }
            };

            req.send(params);
        }

        function authSuccess(accessToken, refreshToken, idToken, fulfillPromise) {
            timeLocal = (timeLocal + new Date().getTime()) / 2;

            setToken(accessToken, refreshToken, idToken, timeLocal);

            if (useNonce && ((kc.tokenParsed && kc.tokenParsed.nonce !== oauth.storedNonce) ||
                (kc.refreshTokenParsed && kc.refreshTokenParsed.nonce !== oauth.storedNonce) ||
                (kc.idTokenParsed && kc.idTokenParsed.nonce !== oauth.storedNonce))) {

                logInfo('[KEYCLOAK] Invalid nonce, clearing token');
                kc.clearToken();
                promise && promise.setError();
            } else {
                if (fulfillPromise) {
                    kc.onAuthSuccess && kc.onAuthSuccess();
                    promise && promise.setSuccess();
                }
            }
        }

    }

    function loadConfig(url) {
        let promise = createPromise();
        let configUrl;

        if (!config) {
            configUrl = 'keycloak.json';
        } else if (typeof config === 'string') {
            configUrl = config;
        }

        function setupOidcEndoints(oidcConfiguration) {
            if (!oidcConfiguration) {
                kc.endpoints = {
                    authorize: function () {
                        return getRealmUrl() + '/protocol/openid-connect/auth';
                    },
                    token: function () {
                        return getRealmUrl() + '/protocol/openid-connect/token';
                    },
                    logout: function () {
                        return getRealmUrl() + '/protocol/openid-connect/logout';
                    },
                    checkSessionIframe: function () {
                        let src = getRealmUrl() + '/protocol/openid-connect/login-status-iframe.html';
                        if (kc.iframeVersion) {
                            src = src + '?version=' + kc.iframeVersion;
                        }
                        return src;
                    },
                    thirdPartyCookiesIframe: function () {
                        let src = getRealmUrl() + '/protocol/openid-connect/3p-cookies/step1.html';
                        if (kc.iframeVersion) {
                            src = src + '?version=' + kc.iframeVersion;
                        }
                        return src;
                    },
                    register: function () {
                        return getRealmUrl() + '/protocol/openid-connect/registrations';
                    },
                    userinfo: function () {
                        return getRealmUrl() + '/protocol/openid-connect/userinfo';
                    }
                };
            } else {
                kc.endpoints = {
                    authorize: function () {
                        return oidcConfiguration.authorization_endpoint;
                    },
                    token: function () {
                        return oidcConfiguration.token_endpoint;
                    },
                    logout: function () {
                        if (!oidcConfiguration.end_session_endpoint) {
                            throw "Not supported by the OIDC server";
                        }
                        return oidcConfiguration.end_session_endpoint;
                    },
                    checkSessionIframe: function () {
                        if (!oidcConfiguration.check_session_iframe) {
                            throw "Not supported by the OIDC server";
                        }
                        return oidcConfiguration.check_session_iframe;
                    },
                    register: function () {
                        throw 'Redirection to "Register user" page not supported in standard OIDC mode';
                    },
                    userinfo: function () {
                        if (!oidcConfiguration.userinfo_endpoint) {
                            throw "Not supported by the OIDC server";
                        }
                        return oidcConfiguration.userinfo_endpoint;
                    }
                };
            }
        }

        if (configUrl) {
            let req = new XMLHttpRequest();
            req.open('GET', configUrl, true);
            req.setRequestHeader('Accept', 'application/json');

            req.onreadystatechange = function () {
                if (req.readyState === 4) {
                    if (req.status === 200 || fileLoaded(req)) {
                        let config = JSON.parse(req.responseText);

                        kc.authServerUrl = config['auth-server-url'];
                        kc.realm = config['realm'];
                        kc.clientId = config['resource'];
                        setupOidcEndoints(null);
                        promise.setSuccess();
                    } else {
                        promise.setError();
                    }
                }
            };

            req.send();
        } else {
            if (!config.clientId) {
                throw 'clientId missing';
            }

            kc.clientId = config.clientId;

            let oidcProvider = config['oidcProvider'];
            if (!oidcProvider) {
                if (!config['url']) {
                    let scripts = document.getElementsByTagName('script');
                    for (let i = 0; i < scripts.length; i++) {
                        if (scripts[i].src.match(/.*keycloak\.js/)) {
                            config.url = scripts[i].src.substr(0, scripts[i].src.indexOf('/js/keycloak.js'));
                            break;
                        }
                    }
                }
                if (!config.realm) {
                    throw 'realm missing';
                }

                kc.authServerUrl = config.url;
                kc.realm = config.realm;
                setupOidcEndoints(null);
                promise.setSuccess();
            } else {
                if (typeof oidcProvider === 'string') {
                    let oidcProviderConfigUrl;
                    if (oidcProvider.charAt(oidcProvider.length - 1) === '/') {
                        oidcProviderConfigUrl = oidcProvider + '.well-known/openid-configuration';
                    } else {
                        oidcProviderConfigUrl = oidcProvider + '/.well-known/openid-configuration';
                    }
                    let req = new XMLHttpRequest();
                    req.open('GET', oidcProviderConfigUrl, true);
                    req.setRequestHeader('Accept', 'application/json');

                    req.onreadystatechange = function () {
                        if (req.readyState === 4) {
                            if (req.status === 200 || fileLoaded(req)) {
                                let oidcProviderConfig = JSON.parse(req.responseText);
                                setupOidcEndoints(oidcProviderConfig);
                                promise.setSuccess();
                            } else {
                                promise.setError();
                            }
                        }
                    };

                    req.send();
                } else {
                    setupOidcEndoints(oidcProvider);
                    promise.setSuccess();
                }
            }
        }

        return promise.promise;
    }

    function fileLoaded(xhr) {
        return xhr.status === 0 && xhr.responseText && xhr.responseURL.startsWith('file:');
    }

    function setToken(token, refreshToken, idToken, timeLocal) {
        if (kc.tokenTimeoutHandle) {
            clearTimeout(kc.tokenTimeoutHandle);
            kc.tokenTimeoutHandle = null;
        }

        if (refreshToken) {
            kc.refreshToken = refreshToken;
            kc.refreshTokenParsed = decodeToken(refreshToken);
        } else {
            delete kc.refreshToken;
            delete kc.refreshTokenParsed;
        }

        if (idToken) {
            kc.idToken = idToken;
            kc.idTokenParsed = decodeToken(idToken);
        } else {
            delete kc.idToken;
            delete kc.idTokenParsed;
        }

        if (token) {
            kc.token = token;
            kc.tokenParsed = decodeToken(token);
            kc.sessionId = kc.tokenParsed.session_state;
            kc.authenticated = true;
            kc.subject = kc.tokenParsed.sub;
            kc.realmAccess = kc.tokenParsed.realm_access;
            kc.resourceAccess = kc.tokenParsed.resource_access;

            if (timeLocal) {
                kc.timeSkew = Math.floor(timeLocal / 1000) - kc.tokenParsed.iat;
            }

            if (kc.timeSkew != null) {

                if (kc.onTokenExpired) {
                    let expiresIn = (kc.tokenParsed['exp'] - (new Date().getTime() / 1000) + kc.timeSkew) * 1000;
                    if (expiresIn <= 0) {
                        kc.onTokenExpired();
                    } else {
                        kc.tokenTimeoutHandle = setTimeout(kc.onTokenExpired, expiresIn);
                    }
                }
            }
        } else {
            delete kc.token;
            delete kc.tokenParsed;
            delete kc.subject;
            delete kc.realmAccess;
            delete kc.resourceAccess;

            kc.authenticated = false;
        }
    }

    function decodeToken(str) {
        str = str.split('.')[1];

        str = str.replace(/-/g, '+');
        str = str.replace(/_/g, '/');
        switch (str.length % 4) {
            case 0:
                break;
            case 2:
                str += '==';
                break;
            case 3:
                str += '=';
                break;
            default:
                throw 'Invalid token';
        }

        str = decodeURIComponent(escape(atob(str)));

        str = JSON.parse(str);
        return str;
    }

    function createUUID() {
        let hexDigits = '0123456789abcdef';
        let s = generateRandomString(36, hexDigits).split("");
        s[14] = '4';
        s[19] = hexDigits.substr((s[19] & 0x3) | 0x8, 1);
        s[8] = s[13] = s[18] = s[23] = '-';
        let uuid = s.join('');
        return uuid;
    }

    function parseCallback(url) {
        let oauth = parseCallbackUrl(url);
        if (!oauth) {
            return;
        }

        let oauthState = callbackStorage.get(oauth.state);

        if (oauthState) {
            oauth.valid = true;
            oauth.redirectUri = oauthState.redirectUri;
            oauth.storedNonce = oauthState.nonce;
            oauth.prompt = oauthState.prompt;
            oauth.pkceCodeVerifier = oauthState.pkceCodeVerifier;
        }

        return oauth;
    }

    function parseCallbackUrl(url) {
        let supportedParams;
        switch (kc.flow) {
            case 'standard':
                supportedParams = ['code', 'state', 'session_state', 'kc_action_status'];
                break;
            case 'implicit':
                supportedParams = ['access_token', 'token_type', 'id_token', 'state', 'session_state', 'expires_in', 'kc_action_status'];
                break;
            case 'hybrid':
                supportedParams = ['access_token', 'token_type', 'id_token', 'code', 'state', 'session_state', 'expires_in', 'kc_action_status'];
                break;
        }

        supportedParams.push('error');
        supportedParams.push('error_description');
        supportedParams.push('error_uri');

        let queryIndex = url.indexOf('?');
        let fragmentIndex = url.indexOf('#');

        let newUrl;
        let parsed;

        if (kc.responseMode === 'query' && queryIndex !== -1) {
            newUrl = url.substring(0, queryIndex);
            parsed = parseCallbackParams(url.substring(queryIndex + 1, fragmentIndex !== -1 ? fragmentIndex : url.length), supportedParams);
            if (parsed.paramsString !== '') {
                newUrl += '?' + parsed.paramsString;
            }
            if (fragmentIndex !== -1) {
                newUrl += url.substring(fragmentIndex);
            }
        } else if (kc.responseMode === 'fragment' && fragmentIndex !== -1) {
            newUrl = url.substring(0, fragmentIndex);
            parsed = parseCallbackParams(url.substring(fragmentIndex + 1), supportedParams);
            if (parsed.paramsString !== '') {
                newUrl += '#' + parsed.paramsString;
            }
        }

        if (parsed && parsed.oauthParams) {
            if (kc.flow === 'standard' || kc.flow === 'hybrid') {
                if ((parsed.oauthParams.code || parsed.oauthParams.error) && parsed.oauthParams.state) {
                    parsed.oauthParams.newUrl = newUrl;
                    return parsed.oauthParams;
                }
            } else if (kc.flow === 'implicit') {
                if ((parsed.oauthParams.access_token || parsed.oauthParams.error) && parsed.oauthParams.state) {
                    parsed.oauthParams.newUrl = newUrl;
                    return parsed.oauthParams;
                }
            }
        }
    }

    function parseCallbackParams(paramsString, supportedParams) {
        let p = paramsString.split('&');
        let result = {
            paramsString: '',
            oauthParams: {}
        };
        for (let i = 0; i < p.length; i++) {
            let split = p[i].indexOf("=");
            let key = p[i].slice(0, split);
            if (supportedParams.indexOf(key) !== -1) {
                result.oauthParams[key] = p[i].slice(split + 1);
            } else {
                if (result.paramsString !== '') {
                    result.paramsString += '&';
                }
                result.paramsString += p[i];
            }
        }
        return result;
    }

    function createPromise() {
        let p = {
            setSuccess: function (result) {
                p.resolve(result);
            },

            setError: function (result) {
                p.reject(result);
            }
        };
        p.promise = new Promise(function (resolve, reject) {
            p.resolve = resolve;
            p.reject = reject;
        });

        return p;
    }

    // Function to extend existing native Promise with timeout
    function applyTimeoutToPromise(promise, timeout, errorMessage) {
        let timeoutHandle = null;
        let timeoutPromise = new Promise(function (resolve, reject) {
            timeoutHandle = setTimeout(function () {
                reject({"error": errorMessage || "Promise is not settled within timeout of " + timeout + "ms"});
            }, timeout);
        });

        return Promise.race([promise, timeoutPromise]).finally(function () {
            clearTimeout(timeoutHandle);
        });
    }

    function setupCheckLoginIframe() {
        let promise = createPromise();

        if (!loginIframe.enable) {
            promise.setSuccess();
            return promise.promise;
        }

        if (loginIframe.iframe) {
            promise.setSuccess();
            return promise.promise;
        }

        let iframe = document.createElement('iframe');
        loginIframe.iframe = iframe;

        iframe.onload = function () {
            let authUrl = kc.endpoints.authorize();
            if (authUrl.charAt(0) === '/') {
                loginIframe.iframeOrigin = getOrigin();
            } else {
                loginIframe.iframeOrigin = authUrl.substring(0, authUrl.indexOf('/', 8));
            }
            promise.setSuccess();
        };

        let src = kc.endpoints.checkSessionIframe();
        iframe.setAttribute('src', src);
        iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
        iframe.setAttribute('title', 'keycloak-session-iframe');
        iframe.style.display = 'none';
        document.body.appendChild(iframe);

        let messageCallback = function (event) {
            if ((event.origin !== loginIframe.iframeOrigin) || (loginIframe.iframe.contentWindow !== event.source)) {
                return;
            }

            if (!(event.data === 'unchanged' || event.data === 'changed' || event.data === 'error')) {
                return;
            }


            if (event.data !== 'unchanged') {
                kc.clearToken();
            }

            let callbacks = loginIframe.callbackList.splice(0, loginIframe.callbackList.length);

            for (let i = callbacks.length - 1; i >= 0; --i) {
                let promise = callbacks[i];
                if (event.data === 'error') {
                    promise.setError();
                } else {
                    promise.setSuccess(event.data === 'unchanged');
                }
            }
        };

        window.addEventListener('message', messageCallback, false);

        return promise.promise;
    }

    function scheduleCheckIframe() {
        if (loginIframe.enable) {
            if (kc.token) {
                setTimeout(function () {
                    checkLoginIframe().then(function (unchanged) {
                        if (unchanged) {
                            scheduleCheckIframe();
                        }
                    });
                }, loginIframe.interval * 1000);
            }
        }
    }

    function checkLoginIframe() {
        let promise = createPromise();

        if (loginIframe.iframe && loginIframe.iframeOrigin) {
            let msg = kc.clientId + ' ' + (kc.sessionId ? kc.sessionId : '');
            loginIframe.callbackList.push(promise);
            let origin = loginIframe.iframeOrigin;
            if (loginIframe.callbackList.length === 1) {
                loginIframe.iframe.contentWindow.postMessage(msg, origin);
            }
        } else {
            promise.setSuccess();
        }

        return promise.promise;
    }

    function check3pCookiesSupported() {
        let promise = createPromise();

        if (loginIframe.enable || kc.silentCheckSsoRedirectUri) {
            let iframe = document.createElement('iframe');
            iframe.setAttribute('src', kc.endpoints.thirdPartyCookiesIframe());
            iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
            iframe.setAttribute('title', 'keycloak-3p-check-iframe');
            iframe.style.display = 'none';
            document.body.appendChild(iframe);

            let messageCallback = function (event) {
                if (iframe.contentWindow !== event.source) {
                    return;
                }

                if (event.data !== "supported" && event.data !== "unsupported") {
                    return;
                } else if (event.data === "unsupported") {
                    logWarn(
                        "[KEYCLOAK] Your browser is blocking access to 3rd-party cookies, this means:\n\n" +
                        " - It is not possible to retrieve tokens without redirecting to the Keycloak server (a.k.a. no support for silent authentication).\n" +
                        " - It is not possible to automatically detect changes to the session status (such as the user logging out in another tab).\n\n" +
                        "For more information see: https://www.keycloak.org/docs/latest/securing_apps/#_modern_browsers"
                    );

                    loginIframe.enable = false;
                    if (kc.silentCheckSsoFallback) {
                        kc.silentCheckSsoRedirectUri = false;
                    }
                }

                document.body.removeChild(iframe);
                window.removeEventListener("message", messageCallback);
                promise.setSuccess();
            };

            window.addEventListener('message', messageCallback, false);
        } else {
            promise.setSuccess();
        }

        return applyTimeoutToPromise(promise.promise, kc.messageReceiveTimeout, "Timeout when waiting for 3rd party check iframe message.");
    }

    function loadAdapter(type) {
        if (!type || type === 'default') {
            return {
                login: function (options) {
                    window.location.assign(kc.createLoginUrl(options));
                    return createPromise().promise;
                },

                logout: function (options) {
                    window.location.replace(kc.createLogoutUrl(options));
                    return createPromise().promise;
                },

                register: function (options) {
                    window.location.assign(kc.createRegisterUrl(options));
                    return createPromise().promise;
                },

                accountManagement: function () {
                    let accountUrl = kc.createAccountUrl();
                    if (typeof accountUrl !== 'undefined') {
                        window.location.href = accountUrl;
                    } else {
                        throw "Not supported by the OIDC server";
                    }
                    return createPromise().promise;
                },

                redirectUri: function (options, encodeHash) {

                    if (options && options.redirectUri) {
                        return options.redirectUri;
                    } else if (kc.redirectUri) {
                        return kc.redirectUri;
                    } else {
                        return location.href;
                    }
                }
            };
        }

        if (type === 'cordova') {
            loginIframe.enable = false;
            let cordovaOpenWindowWrapper = function (loginUrl, target, options) {
                if (window.cordova && window.cordova.InAppBrowser) {
                    // Use inappbrowser for IOS and Android if available
                    return window.cordova.InAppBrowser.open(loginUrl, target, options);
                } else {
                    return window.open(loginUrl, target, options);
                }
            };

            let shallowCloneCordovaOptions = function (userOptions) {
                if (userOptions && userOptions.cordovaOptions) {
                    return Object.keys(userOptions.cordovaOptions).reduce(function (options, optionName) {
                        options[optionName] = userOptions.cordovaOptions[optionName];
                        return options;
                    }, {});
                } else {
                    return {};
                }
            };

            let formatCordovaOptions = function (cordovaOptions) {
                return Object.keys(cordovaOptions).reduce(function (options, optionName) {
                    options.push(optionName + "=" + cordovaOptions[optionName]);
                    return options;
                }, []).join(",");
            };

            let createCordovaOptions = function (userOptions) {
                let cordovaOptions = shallowCloneCordovaOptions(userOptions);
                cordovaOptions.location = 'no';
                if (userOptions && userOptions.prompt === 'none') {
                    cordovaOptions.hidden = 'yes';
                }
                return formatCordovaOptions(cordovaOptions);
            };

            let cordovaRedirectUri = kc.redirectUri || 'http://localhost';

            return {
                login: function (options) {
                    let promise = createPromise();

                    let cordovaOptions = createCordovaOptions(options);
                    let loginUrl = kc.createLoginUrl(options);
                    let ref = cordovaOpenWindowWrapper(loginUrl, '_blank', cordovaOptions);
                    let completed = false;

                    let closed = false;
                    let closeBrowser = function () {
                        closed = true;
                        ref.close();
                    };

                    ref.addEventListener('loadstart', function (event) {
                        if (event.url.indexOf(cordovaRedirectUri) === 0) {
                            let callback = parseCallback(event.url);
                            processCallback(callback, promise);
                            closeBrowser();
                            completed = true;
                        }
                    });

                    ref.addEventListener('loaderror', function (event) {
                        if (!completed) {
                            if (event.url.indexOf(cordovaRedirectUri) === 0) {
                                let callback = parseCallback(event.url);
                                processCallback(callback, promise);
                                closeBrowser();
                                completed = true;
                            } else {
                                promise.setError();
                                closeBrowser();
                            }
                        }
                    });

                    ref.addEventListener('exit', function (event) {
                        if (!closed) {
                            promise.setError({
                                reason: "closed_by_user"
                            });
                        }
                    });

                    return promise.promise;
                },

                logout: function (options) {
                    let promise = createPromise();

                    let logoutUrl = kc.createLogoutUrl(options);
                    let ref = cordovaOpenWindowWrapper(logoutUrl, '_blank', 'location=no,hidden=yes,clearcache=yes');

                    let error;

                    ref.addEventListener('loadstart', function (event) {
                        if (event.url.indexOf(cordovaRedirectUri) === 0) {
                            ref.close();
                        }
                    });

                    ref.addEventListener('loaderror', function (event) {
                        if (event.url.indexOf(cordovaRedirectUri) === 0) {
                            ref.close();
                        } else {
                            error = true;
                            ref.close();
                        }
                    });

                    ref.addEventListener('exit', function (event) {
                        if (error) {
                            promise.setError();
                        } else {
                            kc.clearToken();
                            promise.setSuccess();
                        }
                    });

                    return promise.promise;
                },

                register: function (options) {
                    let promise = createPromise();
                    let registerUrl = kc.createRegisterUrl();
                    let cordovaOptions = createCordovaOptions(options);
                    let ref = cordovaOpenWindowWrapper(registerUrl, '_blank', cordovaOptions);
                    ref.addEventListener('loadstart', function (event) {
                        if (event.url.indexOf(cordovaRedirectUri) === 0) {
                            ref.close();
                            let oauth = parseCallback(event.url);
                            processCallback(oauth, promise);
                        }
                    });
                    return promise.promise;
                },

                accountManagement: function () {
                    let accountUrl = kc.createAccountUrl();
                    if (typeof accountUrl !== 'undefined') {
                        let ref = cordovaOpenWindowWrapper(accountUrl, '_blank', 'location=no');
                        ref.addEventListener('loadstart', function (event) {
                            if (event.url.indexOf(cordovaRedirectUri) === 0) {
                                ref.close();
                            }
                        });
                    } else {
                        throw "Not supported by the OIDC server";
                    }
                },

                redirectUri: function (options) {
                    return cordovaRedirectUri;
                }
            }
        }

        if (type === 'cordova-native') {
            loginIframe.enable = false;

            return {
                login: function (options) {
                    let promise = createPromise();
                    let loginUrl = kc.createLoginUrl(options);

                    universalLinks.subscribe('keycloak', function (event) {
                        universalLinks.unsubscribe('keycloak');
                        window.cordova.plugins.browsertab.close();
                        let oauth = parseCallback(event.url);
                        processCallback(oauth, promise);
                    });

                    window.cordova.plugins.browsertab.openUrl(loginUrl);
                    return promise.promise;
                },

                logout: function (options) {
                    let promise = createPromise();
                    let logoutUrl = kc.createLogoutUrl(options);

                    universalLinks.subscribe('keycloak', function (event) {
                        universalLinks.unsubscribe('keycloak');
                        window.cordova.plugins.browsertab.close();
                        kc.clearToken();
                        promise.setSuccess();
                    });

                    window.cordova.plugins.browsertab.openUrl(logoutUrl);
                    return promise.promise;
                },

                register: function (options) {
                    let promise = createPromise();
                    let registerUrl = kc.createRegisterUrl(options);
                    universalLinks.subscribe('keycloak', function (event) {
                        universalLinks.unsubscribe('keycloak');
                        window.cordova.plugins.browsertab.close();
                        let oauth = parseCallback(event.url);
                        processCallback(oauth, promise);
                    });
                    window.cordova.plugins.browsertab.openUrl(registerUrl);
                    return promise.promise;

                },

                accountManagement: function () {
                    let accountUrl = kc.createAccountUrl();
                    if (typeof accountUrl !== 'undefined') {
                        window.cordova.plugins.browsertab.openUrl(accountUrl);
                    } else {
                        throw "Not supported by the OIDC server";
                    }
                },

                redirectUri: function (options) {
                    if (options && options.redirectUri) {
                        return options.redirectUri;
                    } else if (kc.redirectUri) {
                        return kc.redirectUri;
                    } else {
                        return "http://localhost";
                    }
                }
            }
        }

        throw 'invalid adapter type: ' + type;
    }

    let LocalStorage = function () {
        if (!(this instanceof LocalStorage)) {
            return new LocalStorage();
        }

        localStorage.setItem('kc-test', 'test');
        localStorage.removeItem('kc-test');

        let cs = this;

        function clearExpired() {
            let time = new Date().getTime();
            for (let i = 0; i < localStorage.length; i++) {
                let key = localStorage.key(i);
                if (key && key.indexOf('kc-callback-') === 0) {
                    let value = localStorage.getItem(key);
                    if (value) {
                        try {
                            let expires = JSON.parse(value).expires;
                            if (!expires || expires < time) {
                                localStorage.removeItem(key);
                            }
                        } catch (err) {
                            localStorage.removeItem(key);
                        }
                    }
                }
            }
        }

        cs.get = function (state) {
            if (!state) {
                return;
            }

            let key = 'kc-callback-' + state;
            let value = localStorage.getItem(key);
            if (value) {
                localStorage.removeItem(key);
                value = JSON.parse(value);
            }

            clearExpired();
            return value;
        };

        cs.add = function (state) {
            clearExpired();

            let key = 'kc-callback-' + state.state;
            state.expires = new Date().getTime() + (60 * 60 * 1000);
            localStorage.setItem(key, JSON.stringify(state));
        };
    };

    let CookieStorage = function () {
        if (!(this instanceof CookieStorage)) {
            return new CookieStorage();
        }

        let cs = this;

        cs.get = function (state) {
            if (!state) {
                return;
            }

            let value = getCookie('kc-callback-' + state);
            setCookie('kc-callback-' + state, '', cookieExpiration(-100));
            if (value) {
                return JSON.parse(value);
            }
        };

        cs.add = function (state) {
            setCookie('kc-callback-' + state.state, JSON.stringify(state), cookieExpiration(60));
        };

        cs.removeItem = function (key) {
            setCookie(key, '', cookieExpiration(-100));
        };

        let cookieExpiration = function (minutes) {
            let exp = new Date();
            exp.setTime(exp.getTime() + (minutes * 60 * 1000));
            return exp;
        };

        let getCookie = function (key) {
            let name = key + '=';
            let ca = document.cookie.split(';');
            for (let i = 0; i < ca.length; i++) {
                let c = ca[i];
                while (c.charAt(0) === ' ') {
                    c = c.substring(1);
                }
                if (c.indexOf(name) === 0) {
                    return c.substring(name.length, c.length);
                }
            }
            return '';
        };

        let setCookie = function (key, value, expirationDate) {
            let cookie = key + '=' + value + '; '
                + 'expires=' + expirationDate.toUTCString() + '; ';
            document.cookie = cookie;
        };
    };

    function createCallbackStorage() {
        try {
            return new LocalStorage();
        } catch (err) {
        }

        return new CookieStorage();
    }

    function createLogger(fn) {
        return function () {
            if (kc.enableLogging) {
                fn.apply(console, Array.prototype.slice.call(arguments));
            }
        };
    }
}

export {Keycloak as default};
