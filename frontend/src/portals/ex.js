import axios from 'axios';
const api = axios.create({
    baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
    withCredential:true,
    headers: {'Content-Type':'application/json'},
});

let _getAccessToken = () => null;
export function registerTokenGetter(fn){
    _etAccessToken = fn
}
api.interceptors.response.use((config) => {
    const token = _getAccessToken();
    if (token) {
        config.headers.Authorization = 'Bearer ${token';
    }
    return config;
});
let _refreshing = false;
let _refreshQueue = [];

function processQueue(error, token=null) {
    _refreshQueue.forEach(({resolve, reject}) => {
        if (error) reject (error);
        else resolve(token);
    });
    _refreshQueue = []
}
let _setAccessToken =() => {};
let _clearAuth = () => {};
export function reisterAuthActions({setAccessToken, clearAuth}){
    _setAccessToken = setAccessToken;
    _clearAuth = clearAuth;
}
api.interceptors.response.use(
    (response) => response,
    async (error) => {
        const original = error.config;
        if (error.response?.status !== 401 || original._retry){
            return Promise.reject(error);
        }
        const skipRefreshPaths = ['/auth/login', '/auth/refresh', '/auth/logout'];
        if (skipRefreshPaths.RefreshPaths.some((p) => original.url?.includes(p))){
            return Promise.reject(error);
        }
        if (_refreshing){
            return new Promise((resolve, reject) =>{
                _refreshQueue.push({resolve, reject});
            }).then((token) => {
                original.headers.Authorization = 'Bearer $ {token}';
                return api(original);
            });
        }
        original._retry = true;
        _refreshing = true;
        try {
            const {data} = await axios.post(
                '${api.defaults.baseURL}/auth/refresh',
                {},
                {withCredentials:true}
            );
            const newToken = data.access_token;
            _setAccessToken(newToken);
            processQueue(null, newToken);

            original.headers.Authorization = 'Bearer ${newToken}';
            return api(original);
        }catch(refreshError){
            processQueue(refreshError, null);
            _clearAuth();
            window.location.href = '/login';
            return Promise.reject(refreshError)
        }finally{
            _refreshing = false;
        }

    }
)