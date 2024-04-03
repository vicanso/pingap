import axios, { AxiosRequestConfig, AxiosResponse } from "axios";
import HTTPError from "./http-error";

const requestedAt = "X-Requested-At";
const request = axios.create({
  // 默认超时为10秒
  timeout: 10 * 1000,
});

request.interceptors.request.use(
  (config) => {
    // 对请求的query部分清空值
    if (config.params) {
      Object.keys(config.params).forEach((element) => {
        // 空字符
        if (config.params[element] === "") {
          delete config.params[element];
        }
      });
    }
    config.url = `./api${config.url}`;
    if (config.headers) {
      config.headers[requestedAt] = `${Date.now()}`;
    }
    return config;
  },
  (err) => {
    return Promise.reject(err);
  },
);

// addRequestStats 添加http请求的相关记录
function addRequestStats(
  config: AxiosRequestConfig | undefined,
  res: AxiosResponse | undefined,
  he: HTTPError | undefined,
): void {
  const data: Record<string, unknown> = {};
  if (config) {
    data.method = config.method;
    data.url = config.url;
    data.data = config.data;
    if (config.headers) {
      const value = config.headers[requestedAt];
      data.use = Date.now() - Number(value);
    }
  }
  if (res) {
    data.status = res.status;
  }
  if (he) {
    data.message = he.message;
  }
  // httpRequests.add(data);
}

// 设置接口最少要x ms才完成，能让客户看到loading
const minUse = 300;
const timeoutErrorCodes = ["ECONNABORTED", "ECONNREFUSED", "ECONNRESET"];
request.interceptors.response.use(
  async (res) => {
    addRequestStats(res.config, res, undefined);
    // 根据请求开始时间计算耗时，并判断是否需要延时响应
    if (res.config.method != "get" && res.config.headers) {
      const value = res.config.headers[requestedAt];
      if (value) {
        const use = Date.now() - Number(value);
        if (use >= 0 && use < minUse) {
          await new Promise((resolve) => setTimeout(resolve, minUse - use));
        }
      }
    }
    return res;
  },
  (err) => {
    const { response } = err;
    const he = new HTTPError("Unknown error");
    if (timeoutErrorCodes.includes(err.code)) {
      he.category = "timeout";
      he.message = "Request timeout";
    } else if (response) {
      if (response.data && response.data.message) {
        he.message = response.data.message;
        he.category = response.data.category;
      } else {
        he.exception = true;
        he.category = "exception";
        he.message = "Unknown error";
      }
    }
    addRequestStats(response?.config, response, he);
    return Promise.reject(he);
  },
);

export default request;
