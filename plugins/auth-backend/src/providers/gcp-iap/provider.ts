/*
 * Copyright 2021 Spotify AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AuthenticationError } from '@backstage/errors';
import { JsonValue } from '@backstage/types';
import express from 'express';
import { OAuth2Client, TokenPayload } from 'google-auth-library';
import { Logger } from 'winston';
import { TokenIssuer } from '../../identity/types';
import { CatalogIdentityClient } from '../../lib/catalog';
import { prepareBackstageIdentityResponse } from '../prepareBackstageIdentityResponse';
import {
  AuthHandler,
  AuthProviderFactory,
  AuthProviderRouteHandlers,
  AuthResponse,
  SignInResolver,
} from '../types';

const IAP_JWT_HEADER = 'x-goog-iap-jwt-assertion';

/**
 * The data extracted from an IAP token.
 *
 * @public
 */
export type GcpIapTokenInfo = {
  /**
   * The unique, stable identifier for the user.
   */
  sub: string;
  /**
   * User email address.
   */
  email: string;
  /**
   * Other fields.
   */
  [key: string]: JsonValue;
};

/**
 * The result of the initial auth challenge. This is the input to the auth
 * callbacks.
 *
 * @public
 */
export type GcpIapResult = {
  /**
   * The data extracted from the IAP token header.
   */
  iapToken: GcpIapTokenInfo;
};

/**
 * The provider info to return to the frontend.
 */
export type GcpIapProviderInfo = {
  /**
   * The data extracted from the IAP token header.
   */
  iapToken: GcpIapTokenInfo;
};

/**
 * The shape of the response to return to callers.
 */
export type GcpIapResponse = AuthResponse<GcpIapProviderInfo>;

/**
 * Options for {@link createGcpIapProvider}.
 *
 * @public
 */
export type GcpIapProviderOptions = {
  /**
   * The profile transformation function used to verify and convert the auth
   * response into the profile that will be presented to the user. The default
   * implementation just provides the authenticated email that the IAP
   * presented.
   */
  authHandler?: AuthHandler<GcpIapResult>;

  /**
   * Configures sign-in for this provider.
   */
  signIn: {
    /**
     * Maps an auth result to a Backstage identity for the user.
     */
    resolver: SignInResolver<GcpIapResult>;
  };
};

export async function parseToken(
  jwtToken: unknown,
  audience: string,
  oAuth2Client: OAuth2Client,
): Promise<GcpIapResult> {
  if (typeof jwtToken !== 'string' || !jwtToken) {
    throw new AuthenticationError(
      `Missing Google IAP header: ${IAP_JWT_HEADER}`,
    );
  }

  let payload: TokenPayload | undefined;
  try {
    const response = await oAuth2Client.getIapPublicKeys();
    const ticket = await oAuth2Client.verifySignedJwtWithCertsAsync(
      jwtToken,
      response.pubkeys,
      audience,
      ['https://cloud.google.com/iap'],
    );
    payload = ticket.getPayload();
  } catch (e) {
    throw new AuthenticationError(`Google IAP token verification failed, ${e}`);
  }

  if (!payload) {
    throw new AuthenticationError('Google IAP token had no payload');
  } else if (!payload.sub || !payload.email) {
    throw new AuthenticationError(
      'Google IAP token payload had no sub or email claim',
    );
  }

  return {
    iapToken: {
      ...payload,
      sub: payload.sub,
      email: payload.email,
    },
  };
}

export class GcpIapProvider implements AuthProviderRouteHandlers {
  private readonly audience: string;
  private readonly authHandler: AuthHandler<GcpIapResult>;
  private readonly signInResolver: SignInResolver<GcpIapResult>;
  private readonly tokenIssuer: TokenIssuer;
  private readonly catalogIdentityClient: CatalogIdentityClient;
  private readonly logger: Logger;

  constructor(options: {
    audience: string;
    authHandler: AuthHandler<GcpIapResult>;
    signInResolver: SignInResolver<GcpIapResult>;
    tokenIssuer: TokenIssuer;
    catalogIdentityClient: CatalogIdentityClient;
    logger: Logger;
  }) {
    this.audience = options.audience;
    this.authHandler = options.authHandler;
    this.signInResolver = options.signInResolver;
    this.tokenIssuer = options.tokenIssuer;
    this.catalogIdentityClient = options.catalogIdentityClient;
    this.logger = options.logger;
  }

  async start() {}

  async frameHandler() {}

  async refresh(req: express.Request, res: express.Response): Promise<void> {
    const jwt = req.header(IAP_JWT_HEADER);
    const oAuth2Client = new OAuth2Client();
    const result = await parseToken(jwt, this.audience, oAuth2Client);

    const { profile } = await this.authHandler(result);

    const backstageIdentity = await this.signInResolver(
      { profile, result },
      {
        tokenIssuer: this.tokenIssuer,
        catalogIdentityClient: this.catalogIdentityClient,
        logger: this.logger,
      },
    );

    const response: GcpIapResponse = {
      providerInfo: {
        iapToken: result.iapToken,
      },
      profile,
      backstageIdentity: prepareBackstageIdentityResponse(backstageIdentity),
    };

    res.json(response);
    res.status(200);
    res.end();
  }
}

/**
 * Creates an auth provider for Google Identity-Aware Proxy.
 *
 * @public
 */
export function createGcpIapProvider(
  options: GcpIapProviderOptions,
): AuthProviderFactory {
  return ({ config, tokenIssuer, catalogApi, logger }) => {
    const audience = config.getString('audience');

    const authHandler: AuthHandler<GcpIapResult> =
      options.authHandler ??
      (async ({ iapToken }) => ({ profile: { email: iapToken.email } }));
    const signInResolver = options.signIn.resolver;

    const catalogIdentityClient = new CatalogIdentityClient({
      catalogApi,
      tokenIssuer,
    });

    return new GcpIapProvider({
      audience,
      authHandler,
      signInResolver,
      tokenIssuer,
      catalogIdentityClient,
      logger,
    });
  };
}
