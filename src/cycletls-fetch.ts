import initCycleTLS from 'cycletls';
import debug from 'debug';
import { Headers } from 'headers-polyfill';
import {
  CHROME_USER_AGENT,
  CHROME_JA3,
  CHROME_JA4R,
  CHROME_HTTP2_FINGERPRINT,
  CHROME_HEADER_ORDER,
} from './chrome-fingerprint';

const log = debug('twitter-scraper:cycletls');

let cycleTLSInstance: Awaited<ReturnType<typeof initCycleTLS>> | null = null;

/**
 * Initialize the CycleTLS instance. This should be called once before using the fetch wrapper.
 */
export async function initCycleTLSFetch() {
  if (!cycleTLSInstance) {
    log('Initializing CycleTLS...');
    cycleTLSInstance = await initCycleTLS();
    log('CycleTLS initialized successfully');
  }
  return cycleTLSInstance;
}

/**
 * Cleanup the CycleTLS instance. Call this when you're done making requests.
 */
export function cycleTLSExit() {
  if (cycleTLSInstance) {
    log('Exiting CycleTLS...');
    cycleTLSInstance.exit();
    cycleTLSInstance = null;
  }
}

/**
 * A fetch-compatible wrapper around CycleTLS that mimics Chrome's TLS fingerprint
 * to bypass Cloudflare and other bot detection systems.
 *
 * Extras supported in `init`:
 *   - proxy?: string   // http(s)://user:pass@host:port
 *   - timeout?: number // seconds
 */
export async function cycleTLSFetch(
  input: RequestInfo | URL,
  init?: RequestInit & { proxy?: string; timeout?: number },
): Promise<Response> {
  const instance = await initCycleTLSFetch();

  const url =
    typeof input === 'string'
      ? input
      : input instanceof URL
      ? input.toString()
      : (input as Request).url;
  const method = (init?.method || 'GET').toUpperCase();

  log(`Making ${method} request to ${url}`);

  // Extract headers from RequestInit
  const headers: Record<string, string> = {};
  if (init?.headers) {
    if (init.headers instanceof Headers) {
      init.headers.forEach((value, key) => {
        headers[key] = value;
      });
    } else if (Array.isArray(init.headers)) {
      init.headers.forEach(([key, value]) => {
        headers[key] = value as string;
      });
    } else {
      Object.assign(headers, init.headers as Record<string, string>);
    }
  }

  // Convert body to string if needed
  let body: string | undefined;
  if (init?.body) {
    if (typeof init.body === 'string') {
      body = init.body;
    } else if (init.body instanceof URLSearchParams) {
      body = init.body.toString();
    } else if (init.body instanceof Blob) {
      body = await init.body.text();
    } else {
      body = (init.body as any).toString?.() ?? String(init.body);
    }
  }

  // Proxy & timeout (fallback to env vars if not passed)
  const proxy =
    init?.proxy ||
    process.env.TW_PROXY_URL ||
    process.env.HTTP_PROXY ||
    process.env.http_proxy ||
    '';

  const timeout = typeof init?.timeout === 'number' ? init.timeout : undefined;

  // All Chrome fingerprint constants imported from chrome-fingerprint.ts
  const options: any = {
    body,
    headers,
    ja3: CHROME_JA3,
    ja4r: CHROME_JA4R,
    http2Fingerprint: CHROME_HTTP2_FINGERPRINT,
    headerOrder: CHROME_HEADER_ORDER,
    orderAsProvided: true,
    disableGrease: false,
    userAgent: headers['user-agent'] || CHROME_USER_AGENT,
  };

  if (proxy) {
    options.proxy = proxy;
    log(`Using proxy for CycleTLS: ${proxy}`);
  }
  if (timeout) {
    options.timeout = timeout; // in seconds
  }

  try {
    const response = await instance(
      url,
      options,
      method.toLowerCase() as
        | 'get'
        | 'post'
        | 'put'
        | 'delete'
        | 'patch'
        | 'head'
        | 'options',
    );

    // Convert CycleTLS response to fetch Response
    const responseHeaders = new Headers();
    if (response.headers) {
      Object.entries(response.headers).forEach(([key, value]) => {
        if (Array.isArray(value)) {
          value.forEach((v) => {
            responseHeaders.append(key, v as string);
          });
        } else if (typeof value === 'string') {
          responseHeaders.set(key, value);
        }
      });
    }

    // Body
    let responseBody = '';
    if (typeof response.text === 'function') {
      responseBody = await response.text();
    } else if ((response as any).body) {
      responseBody = (response as any).body;
    }

    return new Response(responseBody, {
      status: response.status,
      statusText: '',
      headers: responseHeaders,
    });
  } catch (error) {
    log(`CycleTLS request failed: ${error}`);
    throw error;
  }
}
