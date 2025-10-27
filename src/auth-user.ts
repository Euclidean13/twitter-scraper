import { Type, type Static } from '@sinclair/typebox';
import { Check } from '@sinclair/typebox/value';
import debug from 'debug';
import { Headers } from 'headers-polyfill';
import * as OTPAuth from 'otpauth';
import { CookieJar } from 'tough-cookie';
import { requestApi } from './api';
import { FetchParameters } from './api-types';
import { TwitterAuthOptions, TwitterGuestAuth } from './auth';
import { ApiError, AuthenticationError, TwitterApiErrorRaw } from './errors';
import { updateCookieJar } from './requests';

const log = debug('twitter-scraper:auth-user');

export interface TwitterUserAuthFlowInitRequest {
  flow_name: string;
  input_flow_data: Record<string, unknown>;
  subtask_versions: Record<string, number>;
}

export interface TwitterUserAuthFlowSubtaskRequest {
  flow_token: string;
  subtask_inputs: ({
    subtask_id: string;
  } & Record<string, unknown>)[];
}

export type TwitterUserAuthFlowRequest =
  | TwitterUserAuthFlowInitRequest
  | TwitterUserAuthFlowSubtaskRequest;

export interface TwitterUserAuthFlowResponse {
  errors?: TwitterApiErrorRaw[];
  flow_token?: string;
  status?: string;
  subtasks?: TwitterUserAuthSubtask[];

  // When risk is higher, Twitter can return a top-level js_instrumentation
  // directive with a URL to fetch. You must fetch and echo that body.
  js_instrumentation?: {
    url: string;
    timeout_ms: number;
    next_link?: { link_type: string; link_id: string };
  };
}

interface TwitterUserAuthVerifyCredentials {
  errors?: TwitterApiErrorRaw[];
}

const TwitterUserAuthSubtask = Type.Object({
  subtask_id: Type.String(),
  enter_text: Type.Optional(Type.Object({})),
});
type TwitterUserAuthSubtask = Static<typeof TwitterUserAuthSubtask>;

export type FlowTokenResultSuccess = {
  status: 'success';
  response: TwitterUserAuthFlowResponse;
};

export type FlowTokenResultError = {
  status: 'error';
  err: Error;
};

export type FlowTokenResult = FlowTokenResultSuccess | FlowTokenResultError;

export interface TwitterUserAuthCredentials {
  username: string;
  password: string;
  email?: string;
  twoFactorSecret?: string;
}

/**
 * The API interface provided to custom subtask handlers for interacting with the Twitter authentication flow.
 */
export interface FlowSubtaskHandlerApi {
  sendFlowRequest: (
    request: TwitterUserAuthFlowRequest,
  ) => Promise<FlowTokenResult>;
  getFlowToken: () => string;
}

/**
 * A handler function for processing Twitter authentication flow subtasks.
 */
export type FlowSubtaskHandler = (
  subtaskId: string,
  previousResponse: TwitterUserAuthFlowResponse,
  credentials: TwitterUserAuthCredentials,
  api: FlowSubtaskHandlerApi,
) => Promise<FlowTokenResult>;

/**
 * A user authentication token manager.
 */
export class TwitterUserAuth extends TwitterGuestAuth {
  private readonly subtaskHandlers: Map<string, FlowSubtaskHandler> = new Map();

  constructor(bearerToken: string, options?: Partial<TwitterAuthOptions>) {
    super(bearerToken, options);
    this.initializeDefaultHandlers();
  }

  /**
   * Register a custom subtask handler or override an existing one
   */
  registerSubtaskHandler(subtaskId: string, handler: FlowSubtaskHandler): void {
    this.subtaskHandlers.set(subtaskId, handler);
  }

  private initializeDefaultHandlers(): void {
    this.subtaskHandlers.set(
      'LoginJsInstrumentationSubtask',
      this.handleJsInstrumentationSubtask.bind(this),
    );
    this.subtaskHandlers.set(
      'LoginEnterUserIdentifierSSO',
      this.handleEnterUserIdentifierSSO.bind(this),
    );
    this.subtaskHandlers.set(
      'LoginEnterAlternateIdentifierSubtask',
      this.handleEnterAlternateIdentifierSubtask.bind(this),
    );
    this.subtaskHandlers.set(
      'LoginEnterPassword',
      this.handleEnterPassword.bind(this),
    );
    this.subtaskHandlers.set(
      'AccountDuplicationCheck',
      this.handleAccountDuplicationCheck.bind(this),
    );
    this.subtaskHandlers.set(
      'LoginTwoFactorAuthChallenge',
      this.handleTwoFactorAuthChallenge.bind(this),
    );
    this.subtaskHandlers.set('LoginAcid', this.handleAcid.bind(this));
    this.subtaskHandlers.set(
      'LoginSuccessSubtask',
      this.handleSuccessSubtask.bind(this),
    );

    // Explicit handlers for occasionally inserted subtasks so failures are clear
    this.subtaskHandlers.set(
      'EnterRecaptcha',
      this.handleEnterRecaptcha.bind(this),
    );
    this.subtaskHandlers.set(
      'PhoneVerification',
      this.handlePhoneVerification.bind(this),
    );
    this.subtaskHandlers.set('SecurityKey', this.handleSecurityKey.bind(this));

    // Best-effort pass-throughs for benign UI subtasks
    this.subtaskHandlers.set('WaitSpinner', this.handleWaitSpinner.bind(this));
    this.subtaskHandlers.set('GenericUrt', this.handleGenericUrt.bind(this));
    this.subtaskHandlers.set('WebModal', this.handleWebModal.bind(this));
    this.subtaskHandlers.set('OpenLink', this.handleOpenLink.bind(this));
  }

  async isLoggedIn(): Promise<boolean> {
    const res = await requestApi<TwitterUserAuthVerifyCredentials>(
      'https://api.x.com/1.1/account/verify_credentials.json',
      this,
    );
    if (!res.success) return false;
    const { value: verify } = res;
    return verify && !verify.errors?.length;
  }

  async login(
    username: string,
    password: string,
    email?: string,
    twoFactorSecret?: string,
  ): Promise<void> {
    await this.updateGuestToken();
    await this.seedCookies();

    const credentials: TwitterUserAuthCredentials = {
      username,
      password,
      email,
      twoFactorSecret,
    };

    const runOnce = async (): Promise<FlowTokenResult> => {
      let next: FlowTokenResult = await this.initLogin();

      // tiny human-like delay after init
      await this.sleep(200, 600);

      while (next.status === 'success' && next.response.subtasks?.length) {
        const flowToken = next.response.flow_token;
        if (flowToken == null) throw new Error('flow_token not found.');

        const subtaskId = next.response.subtasks[0].subtask_id;
        log(`Auth subtask: ${subtaskId}`);

        const handler = this.subtaskHandlers.get(subtaskId);
        if (!handler) throw new Error(`Unknown subtask ${subtaskId}`);

        // small pacing between subtasks
        await this.sleep(200, 600);

        next = await handler(subtaskId, next.response, credentials, {
          sendFlowRequest: this.executeFlowTask.bind(this),
          getFlowToken: () => flowToken!,
        });
      }
      return next;
    };

    // First attempt
    let result = await runOnce();
    if (result.status === 'success') return;

    // If we failed with a 399-style AuthenticationError, try a single restart
    const msg = String(result.err?.message ?? '');
    const is399 =
      /Auth 399|Authentication error \(399\)|generic incorrect\/risk/i.test(
        msg,
      );

    if (is399) {
      // brief cooloff to let cf_bm/ct0 stabilize
      await this.sleep(1200, 1800);
      await this.seedCookies();
      result = await runOnce();
      if (result.status === 'success') return;
    }

    throw result.err;
  }

  async logout(): Promise<void> {
    if (!this.hasToken()) return;

    try {
      await requestApi<void>(
        'https://api.x.com/1.1/account/logout.json',
        this,
        'POST',
      );
    } catch (error) {
      console.warn('Error during logout:', error);
    } finally {
      this.deleteToken();
      this.jar = new CookieJar();
    }
  }

  async installCsrfToken(headers: Headers): Promise<void> {
    const cookies = await this.getCookies();
    const xCsrfToken = cookies.find((cookie) => cookie.key === 'ct0');
    if (xCsrfToken) {
      headers.set('x-csrf-token', xCsrfToken.value);
    }
  }

  async installTo(headers: Headers): Promise<void> {
    headers.set('authorization', `Bearer ${this.bearerToken}`);
    const cookie = await this.getCookieString();
    headers.set('cookie', cookie);
    if (this.guestToken) {
      headers.set('x-guest-token', this.guestToken);
    }
    await this.installCsrfToken(headers);
  }

  private async seedCookies(): Promise<void> {
    try {
      const res = await this.fetch('https://x.com/', {
        method: 'GET',
        credentials: 'include',
      } as any);
      await updateCookieJar(this.jar, res.headers);
    } catch (e) {
      log('Cookie pre-seed failed (continuing): %O', e);
    }
  }

  private async initLogin(): Promise<FlowTokenResult> {
    // Leave ct0 and __cf_bm intact; wiping them causes intermittent 399s.
    this.removeCookie('twitter_ads_id=');
    this.removeCookie('ads_prefs=');
    this.removeCookie('_twitter_sess=');
    this.removeCookie('zipbox_forms_auth_token=');
    this.removeCookie('lang=');
    this.removeCookie('bouncer_reset_cookie=');
    this.removeCookie('twid=');
    this.removeCookie('twitter_ads_idb=');
    this.removeCookie('email_uid=');
    this.removeCookie('external_referer=');
    // DO NOT REMOVE ct0
    this.removeCookie('aa_u=');
    // DO NOT REMOVE __cf_bm

    return await this.executeFlowTask({
      flow_name: 'login',
      input_flow_data: {
        flow_context: {
          debug_overrides: {},
          start_location: {
            location: 'unknown',
          },
        },
      },
      subtask_versions: {
        action_list: 2,
        alert_dialog: 1,
        app_download_cta: 1,
        check_logged_in_account: 1,
        choice_selection: 3,
        contacts_live_sync_permission_prompt: 0,
        cta: 7,
        email_verification: 2,
        end_flow: 1,
        enter_date: 1,
        enter_email: 2,
        enter_password: 5,
        enter_phone: 2,
        enter_recaptcha: 1,
        enter_text: 5,
        enter_username: 2,
        generic_urt: 3,
        in_app_notification: 1,
        interest_picker: 3,
        js_instrumentation: 1,
        menu_dialog: 1,
        notifications_permission_prompt: 2,
        open_account: 2,
        open_home_timeline: 1,
        open_link: 1,
        phone_verification: 4,
        privacy_options: 1,
        security_key: 3,
        select_avatar: 4,
        select_banner: 2,
        settings_list: 7,
        show_code: 1,
        sign_up: 2,
        sign_up_review: 4,
        tweet_selection_urt: 1,
        update_users: 1,
        upload_media: 1,
        user_recommendations_list: 4,
        user_recommendations_urt: 1,
        wait_spinner: 3,
        web_modal: 1,
      },
    });
  }

  // --- Subtasks ---

  // IMPORTANT: actually fetch and echo the instrumentation payload if server asks for it.
  private async handleJsInstrumentationSubtask(
    subtaskId: string,
    prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    const ins = prev.js_instrumentation;
    let responsePayload = '{}';

    if (ins?.url) {
      try {
        const budgetMs = Math.max(250, Math.min(ins.timeout_ms ?? 2000, 4000));
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), budgetMs);

        const res = await this.fetch(ins.url, {
          method: 'GET',
          credentials: 'include',
          headers: {
            accept: '*/*',
            referer: 'https://x.com/',
          } as any,
          signal: ctrl.signal,
        } as any);

        clearTimeout(t);
        responsePayload = await res.text();
        if (!responsePayload || responsePayload.trim() === '')
          responsePayload = '{}';
      } catch (e) {
        log(
          'JS instrumentation fetch failed, falling back to {}. Error: %O',
          e,
        );
        responsePayload = '{}';
      }
    } else {
      // low-risk path: send a non-empty minimal payload
      responsePayload = JSON.stringify({
        js: true,
        ts: Date.now(),
        rnd: Math.floor(Math.random() * 1e7),
      });
    }

    return await api.sendFlowRequest({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          js_instrumentation: {
            response: responsePayload,
            link: 'next_link',
          },
        },
      ],
    });
  }

  private async handleEnterAlternateIdentifierSubtask(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await this.executeFlowTask({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          enter_text: {
            text: credentials.email,
            link: 'next_link',
          },
        },
      ],
    });
  }

  private async handleEnterUserIdentifierSSO(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await this.executeFlowTask({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          settings_list: {
            setting_responses: [
              {
                key: 'user_identifier',
                response_data: {
                  text_data: { result: credentials.username },
                },
              },
            ],
            link: 'next_link',
          },
        },
      ],
    });
  }

  private async handleEnterPassword(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await this.executeFlowTask({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          enter_password: {
            password: credentials.password,
            link: 'next_link',
          },
        },
      ],
    });
  }

  private async handleAccountDuplicationCheck(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await this.executeFlowTask({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          check_logged_in_account: {
            link: 'AccountDuplicationCheck_false',
          },
        },
      ],
    });
  }

  private async handleTwoFactorAuthChallenge(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    if (!credentials.twoFactorSecret) {
      return {
        status: 'error',
        err: new AuthenticationError(
          'Two-factor authentication is required but no secret was provided',
        ),
      };
    }

    const totp = new OTPAuth.TOTP({ secret: credentials.twoFactorSecret });
    let lastError: FlowTokenResultError | undefined;

    for (let attempts = 1; attempts <= 3; attempts++) {
      const code = totp.generate();
      const res = await api.sendFlowRequest({
        flow_token: api.getFlowToken(),
        subtask_inputs: [
          {
            subtask_id: subtaskId,
            enter_text: {
              link: 'next_link',
              text: code,
            },
          },
        ],
      });

      if (res.status === 'success') return res;

      lastError = res;
      await this.sleep(1000 * attempts, 1000 * attempts + 500); // roll into next TOTP window if near-edge
    }

    return (
      lastError ?? {
        status: 'error',
        err: new AuthenticationError(
          'Two-factor authentication failed after retries',
        ),
      }
    );
  }

  private async handleAcid(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await this.executeFlowTask({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          enter_text: {
            text: credentials.email,
            link: 'next_link',
          },
        },
      ],
    });
  }

  private async handleSuccessSubtask(
    _subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await this.executeFlowTask({
      flow_token: api.getFlowToken(),
      subtask_inputs: [],
    });
  }

  // ----- Extra, explicit handlers -----

  private async handleEnterRecaptcha(
    _subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    _api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return {
      status: 'error',
      err: new AuthenticationError(
        'Recaptcha challenge encountered. Interactive solving is required.',
      ),
    };
  }

  private async handlePhoneVerification(
    _subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    _api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return {
      status: 'error',
      err: new AuthenticationError(
        'Phone verification required for this login (SMS/Call).',
      ),
    };
  }

  private async handleSecurityKey(
    _subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    _api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return {
      status: 'error',
      err: new AuthenticationError(
        'Security key (FIDO/U2F) challenge required for this login.',
      ),
    };
  }

  private async handleWaitSpinner(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await api.sendFlowRequest({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          wait_spinner: { link: 'next_link' },
        },
      ],
    });
  }

  private async handleGenericUrt(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await api.sendFlowRequest({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          generic_urt: { link: 'next_link' },
        },
      ],
    });
  }

  private async handleWebModal(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await api.sendFlowRequest({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          web_modal: { link: 'next_link' },
        },
      ],
    });
  }

  private async handleOpenLink(
    subtaskId: string,
    _prev: TwitterUserAuthFlowResponse,
    _credentials: TwitterUserAuthCredentials,
    api: FlowSubtaskHandlerApi,
  ): Promise<FlowTokenResult> {
    return await api.sendFlowRequest({
      flow_token: api.getFlowToken(),
      subtask_inputs: [
        {
          subtask_id: subtaskId,
          open_link: { link: 'next_link' },
        },
      ],
    });
  }

  // ----- Core task executor -----

  private async executeFlowTask(
    data: TwitterUserAuthFlowRequest,
  ): Promise<FlowTokenResult> {
    let onboardingTaskUrl = 'https://api.x.com/1.1/onboarding/task.json';
    if ('flow_name' in data) {
      onboardingTaskUrl = `https://api.x.com/1.1/onboarding/task.json?flow_name=${data.flow_name}`;
    }

    log(`Making POST request to ${onboardingTaskUrl}`);

    const token = this.guestToken;
    if (token == null) {
      throw new AuthenticationError(
        'Authentication token is null or undefined.',
      );
    }

    // Keep UA and CH hints internally consistent; adjust as needed for your environment.
    const headers = new Headers({
      accept: '*/*',
      'accept-language': 'en-US,en;q=0.9',
      'content-type': 'application/json',
      'cache-control': 'no-cache',
      origin: 'https://x.com',
      pragma: 'no-cache',
      priority: 'u=1, i',
      referer: 'https://x.com/',
      'sec-ch-ua':
        '"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'empty',
      'sec-fetch-mode': 'cors',
      'sec-fetch-site': 'same-origin',
      'user-agent':
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
      'x-guest-token': token,
      'x-twitter-auth-type': 'OAuth2Client',
      'x-twitter-active-user': 'yes',
      'x-twitter-client-language': 'en',
    });
    await this.installTo(headers);

    let res: Response;
    do {
      const fetchParameters: FetchParameters = [
        onboardingTaskUrl,
        {
          credentials: 'include',
          method: 'POST',
          headers: headers,
          body: JSON.stringify(data),
        },
      ];

      try {
        res = await this.fetch(...fetchParameters);
      } catch (err) {
        if (!(err instanceof Error)) throw err;
        return { status: 'error', err };
      }

      await updateCookieJar(this.jar, res.headers);

      if (res.status === 429) {
        log('Rate limit hit, waiting before retrying...');
        await this.onRateLimit({
          fetchParameters: fetchParameters,
          response: res,
        });
      }
    } while (res.status === 429);

    if (!res.ok) {
      return { status: 'error', err: await ApiError.fromResponse(res) };
    }

    const flow: TwitterUserAuthFlowResponse = await res.json();

    if (flow?.flow_token == null) {
      return {
        status: 'error',
        err: new AuthenticationError('flow_token not found.'),
      };
    }

    // Surface 399 explicitly so the caller can retry the whole flow once.
    if (flow.errors?.length) {
      const e = flow.errors[0];
      if (e.code === 399) {
        return {
          status: 'error',
          err: new AuthenticationError(
            `Auth 399 (generic incorrect/risk). Message=${e.message}`,
          ),
        };
      }
      return {
        status: 'error',
        err: new AuthenticationError(
          `Authentication error (${e.code}): ${e.message}`,
        ),
      };
    }

    if (typeof flow.flow_token !== 'string') {
      return {
        status: 'error',
        err: new AuthenticationError('flow_token was not a string.'),
      };
    }

    const subtask = flow.subtasks?.length ? flow.subtasks[0] : undefined;
    Check(TwitterUserAuthSubtask, subtask);

    if (subtask && subtask.subtask_id === 'DenyLoginSubtask') {
      return {
        status: 'error',
        err: new AuthenticationError('Authentication error: DenyLoginSubtask'),
      };
    }

    return { status: 'success', response: flow };
  }

  // ----- tiny helpers -----

  private async sleep(minMs: number, maxMs: number): Promise<void> {
    const ms = minMs + Math.floor(Math.random() * Math.max(0, maxMs - minMs));
    return new Promise((r) => setTimeout(r, ms));
  }
}
